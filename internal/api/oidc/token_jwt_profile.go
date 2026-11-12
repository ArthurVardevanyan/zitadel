package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/api/oidc/wif"
	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func (s *Server) JWTProfile(ctx context.Context, r *op.Request[oidc.JWTProfileGrantRequest]) (_ *op.Response, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() {
		span.EndWithError(err)
		err = oidcError(ctx, err)
	}()

	user, err := s.verifyJWTProfile(ctx, r.Data)
	if err != nil {
		return nil, err
	}

	client := &clientCredentialsClient{
		clientID:      user.Username,
		userID:        user.UserID,
		resourceOwner: user.ResourceOwner,
		tokenType:     user.TokenType,
	}
	scope, err := op.ValidateAuthReqScopes(client, r.Data.Scope)
	if err != nil {
		return nil, err
	}
	scope, err = s.checkOrgScopes(ctx, client.resourceOwner, scope)
	if err != nil {
		return nil, err
	}

	session, err := s.command.CreateOIDCSession(ctx,
		client.userID,
		client.resourceOwner,
		client.clientID,
		"", // backChannelLogoutURI not needed for service account session
		scope,
		domain.AddAudScopeToAudience(ctx, nil, r.Data.Scope),
		[]domain.UserAuthMethodType{domain.UserAuthMethodTypePrivateKey},
		time.Now(),
		"",
		nil,
		nil,
		domain.TokenReasonJWTProfile,
		nil,
		false,
		"",
		domain.OIDCResponseTypeUnspecified,
	)
	if err != nil {
		return nil, err
	}
	return response(s.accessTokenResponseFromSession(ctx, client, session, "", "", false, true, true, false))
}

func (s *Server) verifyJWTProfile(ctx context.Context, req *oidc.JWTProfileGrantRequest) (_ *query.AuthNKeyUser, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	// Workload identity federation: when a configuration owned by a service
	// user trusts the iss of the assertion, it is authenticated against that
	// configuration instead of the user's registered keys. Routing on the
	// unverified iss is safe: the signature is only ever checked against the
	// keys of exactly that configured issuer, and Zitadel issued JWT profile
	// assertions carry the user id as iss, never an https issuer URL.
	if issuer := unverifiedIssuer(req.Assertion); issuer != "" {
		user, handled, wifErr := s.verifyFederatedAssertion(ctx, req.Assertion, issuer)
		if handled {
			if wifErr != nil {
				return nil, oidc.ErrInvalidGrant().WithParent(wifErr).WithReturnParentToClient(authz.GetFeatures(ctx).DebugOIDCParentError).WithDescription("invalid federated assertion")
			}
			return user, nil
		}
	}

	storage := &jwtProfileKeyStorage{query: s.query}
	verifier := op.NewJWTProfileVerifier(
		storage, op.IssuerFromContext(ctx),
		time.Hour, time.Second,
	)
	_, err = op.VerifyJWTAssertion(ctx, req.Assertion, verifier)
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithParent(err).WithReturnParentToClient(authz.GetFeatures(ctx).DebugOIDCParentError).WithDescription("invalid assertion")
	}
	return storage.user, nil
}

// unverifiedIssuer extracts the iss claim of a compact JWS without any
// validation. It only decides which authentication flow an assertion enters;
// the claim itself is never trusted, every flow validates it again.
func unverifiedIssuer(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Issuer
}

// verifyFederatedAssertion authenticates an assertion from an external OIDC
// issuer against every active workload identity federation configuration
// registered for that iss. Configurations owned by an application do not
// participate in this grant, only service user owners do. Exactly one
// distinct owner must pass validation; multiple matching owners are refused
// so overlapping subject conditions can never straddle identities. handled
// reports whether any service user configuration exists for the issuer:
// without one the assertion is not a workload identity assertion and the
// caller falls back to the Zitadel issued JWT profile flow. Once handled,
// a failure is final and never falls back.
func (s *Server) verifyFederatedAssertion(ctx context.Context, assertion, issuer string) (_ *query.AuthNKeyUser, handled bool, err error) {
	if s.wifVerifier == nil {
		return nil, false, nil
	}
	identities, err := s.query.ActiveWorkloadIdentitiesByIssuer(ctx, issuer)
	if err != nil {
		return nil, false, err
	}

	var ownerID string
	for _, identity := range identities {
		if identity.OwnerType != domain.WorkloadIdentityOwnerTypeServiceUser {
			continue
		}
		handled = true
		if _, err := s.wifVerifier.Verify(ctx, assertion, wifRuleFromWorkloadIdentity(identity)); err != nil {
			continue
		}
		switch {
		case ownerID == "":
			ownerID = identity.OwnerID
		case ownerID != identity.OwnerID:
			return nil, true, zerrors.ThrowPermissionDenied(nil, "OIDC-wif1", "Errors.WorkloadIdentity.AssertionAmbiguous")
		}
	}
	if ownerID == "" {
		return nil, true, zerrors.ThrowPermissionDenied(nil, "OIDC-wif2", "Errors.WorkloadIdentity.AssertionRejected")
	}

	user, err := s.query.GetUserByID(ctx, false, ownerID)
	if err != nil {
		return nil, true, err
	}
	if user.State != domain.UserStateActive || user.Type != domain.UserTypeMachine {
		return nil, true, zerrors.ThrowPreconditionFailed(nil, "OIDC-wif3", "Errors.WorkloadIdentity.OwnerInactive")
	}
	tokenType := domain.OIDCTokenTypeJWT
	if user.Machine != nil {
		tokenType = user.Machine.AccessTokenType
	}
	return &query.AuthNKeyUser{
		UserID:        user.ID,
		ResourceOwner: user.ResourceOwner,
		Username:      user.Username,
		TokenType:     tokenType,
	}, true, nil
}

// wifRuleFromWorkloadIdentity maps a projected federation configuration onto
// the verifier's rule representation.
func wifRuleFromWorkloadIdentity(identity *query.WorkloadIdentity) *wif.Rule {
	return &wif.Rule{
		Issuer:            identity.Issuer,
		JwksURI:           identity.JwksURI,
		Audiences:         []string(identity.Audiences),
		SubjectConditions: []domain.SubjectCondition(identity.SubjectConditions),
		Algorithms:        []string(identity.Algorithms),
	}
}

type jwtProfileKeyStorage struct {
	query *query.Queries
	user  *query.AuthNKeyUser // only populated after GetKeyByIDAndClientID is called
}

func (s *jwtProfileKeyStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, userID string) (_ *jose.JSONWebKey, err error) {
	s.user, err = s.query.GetAuthNKeyUser(ctx, keyID, userID)
	if err != nil {
		return nil, err
	}
	publicKey, err := crypto.BytesToPublicKey(s.user.PublicKey)
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKey{
		KeyID: keyID,
		Use:   "sig",
		Key:   publicKey,
	}, nil
}

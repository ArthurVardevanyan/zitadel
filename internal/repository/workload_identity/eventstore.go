package workload_identity

import (
	"github.com/zitadel/zitadel/internal/eventstore"
)

func init() {
	eventstore.RegisterFilterEventMapper(AggregateType, WorkloadIdentityAddedEventType, WorkloadIdentityAddedEventMapper)
	eventstore.RegisterFilterEventMapper(AggregateType, WorkloadIdentityChangedEventType, WorkloadIdentityChangedEventMapper)
	eventstore.RegisterFilterEventMapper(AggregateType, WorkloadIdentityRemovedEventType, WorkloadIdentityRemovedEventMapper)
}

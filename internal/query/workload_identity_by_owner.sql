select id,
		creation_date,
		change_date,
		resource_owner,
		sequence,
		owner_type,
		owner_id,
		name,
		issuer,
		jwks_uri,
		audiences,
		subject_conditions,
		algorithms,
		state
from projections.workload_identities1
where instance_id = $1
	and owner_type = $2
	and owner_id = $3
order by creation_date

package domain

import "strconv"

func UpgradeV1(a Aggregate) (Aggregate, error) {
	validated, err := Validate(a)
	if err != nil {
		return Aggregate{}, err
	}
	a = validated.Snapshot()
	if a.SchemaVersion == 2 {
		return a, nil
	}
	if a.SchemaVersion != 1 {
		return Aggregate{}, ErrInvalidAggregate
	}
	a.SchemaVersion = 2
	for i := range a.MailJobs {
		a.MailJobs[i].Purpose = "otp"
		a.MailJobs[i].EnqueueOrder = Version(strconv.Itoa(i + 1))
	}
	for i := range a.Idempotency {
		a.Idempotency[i].ContractProfile = "C2"
	}
	if _, err := Validate(a); err != nil {
		return Aggregate{}, err
	}
	return a, nil
}

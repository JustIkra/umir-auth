package domain

func UpgradeRegistration(a Aggregate) (Aggregate, error) {
	v, err := Validate(a)
	if err != nil {
		return Aggregate{}, err
	}
	a = v.Snapshot()
	if a.SchemaVersion == 1 {
		a, err = UpgradeV1(a)
		if err != nil {
			return Aggregate{}, err
		}
	}
	a.SchemaVersion = 3
	if _, err := Validate(a); err != nil {
		return Aggregate{}, err
	}
	return a, nil
}

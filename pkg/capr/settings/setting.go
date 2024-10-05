package settings

type Setting struct {
	Get     func() string
	Default string
}

func NewSetting(get func() string, d string) Setting {
	return Setting{
		Get:     get,
		Default: d,
	}
}

package output

type Colorizer struct {
	Bold   string
	Red    string
	Yellow string
	Green  string
	Cyan   string
	Dim    string
	Reset  string
}

func NewColorizer(noColor bool) *Colorizer {
	if noColor {
		return &Colorizer{}
	}

	return &Colorizer{
		Bold:   "\033[1m",
		Red:    "\033[31m",
		Yellow: "\033[33m",
		Green:  "\033[32m",
		Cyan:   "\033[36m",
		Dim:    "\033[2m",
		Reset:  "\033[0m",
	}
}

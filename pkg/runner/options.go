package runner

import "flag"

type Options struct {
	Verbose     bool
	RootList    string
	Debug       bool
	JsonOutput  bool
	Concurrency int
	RateLimit   int // New field for rate limit in seconds
}

func ParseOptions() *Options {
	options := &Options{}

	flag.StringVar(&options.RootList, "r", "", "Path to the list of root domains to filter against")
	flag.BoolVar(&options.Verbose, "v", false, "Output go logs (500/429 errors) to command line")
	flag.BoolVar(&options.Debug, "debug", false, "Debug CT logs to see if you are keeping up")
	flag.BoolVar(&options.JsonOutput, "j", false, "JSONL output cert info")
	flag.IntVar(&options.Concurrency, "concurrency", 5, "Number of concurrent workers")
	flag.IntVar(&options.RateLimit, "seconds", 120, "Rate limit in seconds for log fetching")
	flag.Parse()

	return options
}
                                            

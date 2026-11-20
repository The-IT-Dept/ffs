package catalog

// WithOutputLimit bounds the worker output ExecRunner reads, so tests need not produce 65 MiB.
var WithOutputLimit = withOutputLimit

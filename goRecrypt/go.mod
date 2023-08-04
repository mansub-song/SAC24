module gorecrypt

go 1.20

require (
	github.com/SherLzp/goRecrypt v0.0.0-20200405110533-a55273ae0aeb
	golang.org/x/crypto v0.11.0
)

require golang.org/x/sys v0.10.0 // indirect

replace github.com/SherLzp/goRecrypt => ./

// replace github.com/SherLzp/goRecrypt/recrypt => ./recrypt

// replace github.com/SherLzp/goRecrypt/curve => ./curve

package data

// Code generated by go-ipld-prime gengo.  DO NOT EDIT.

import (
	ipld "github.com/ipld/go-ipld-prime"
)

var _ ipld.Node = nil // suppress errors when this dependency is not referenced
// Type is a struct embeding a NodePrototype/Type for every Node implementation in this package.
// One of its major uses is to start the construction of a value.
// You can use it like this:
//
//	data.Type.YourTypeName.NewBuilder().BeginMap() //...
//
// and:
//
//	data.Type.OtherTypeName.NewBuilder().AssignString("x") // ...
var Type typeSlab

type typeSlab struct {
	BlockSizes           _BlockSizes__Prototype
	BlockSizes__Repr     _BlockSizes__ReprPrototype
	Bytes                _Bytes__Prototype
	Bytes__Repr          _Bytes__ReprPrototype
	Int                  _Int__Prototype
	Int__Repr            _Int__ReprPrototype
	String               _String__Prototype
	String__Repr         _String__ReprPrototype
	UnixFSData           _UnixFSData__Prototype
	UnixFSData__Repr     _UnixFSData__ReprPrototype
	UnixFSMetadata       _UnixFSMetadata__Prototype
	UnixFSMetadata__Repr _UnixFSMetadata__ReprPrototype
	UnixTime             _UnixTime__Prototype
	UnixTime__Repr       _UnixTime__ReprPrototype
}

// --- type definitions follow ---

// BlockSizes matches the IPLD Schema type "BlockSizes".  It has list kind.
type BlockSizes = *_BlockSizes
type _BlockSizes struct {
	x []_Int
}

// Bytes matches the IPLD Schema type "Bytes".  It has bytes kind.
type Bytes = *_Bytes
type _Bytes struct{ x []byte }

// Int matches the IPLD Schema type "Int".  It has int kind.
type Int = *_Int
type _Int struct{ x int64 }

// String matches the IPLD Schema type "String".  It has string kind.
type String = *_String
type _String struct{ x string }

// UnixFSData matches the IPLD Schema type "UnixFSData".  It has Struct type-kind, and may be interrogated like map kind.
type UnixFSData = *_UnixFSData
type _UnixFSData struct {
	DataType   _Int
	Data       _Bytes__Maybe
	FileSize   _Int__Maybe
	BlockSizes _BlockSizes
	HashType   _Int__Maybe
	Fanout     _Int__Maybe
	Mode       _Int__Maybe
	Mtime      _UnixTime__Maybe
}

// UnixFSMetadata matches the IPLD Schema type "UnixFSMetadata".  It has Struct type-kind, and may be interrogated like map kind.
type UnixFSMetadata = *_UnixFSMetadata
type _UnixFSMetadata struct {
	MimeType _String__Maybe
}

// UnixTime matches the IPLD Schema type "UnixTime".  It has Struct type-kind, and may be interrogated like map kind.
type UnixTime = *_UnixTime
type _UnixTime struct {
	Seconds               _Int
	FractionalNanoseconds _Int__Maybe
}

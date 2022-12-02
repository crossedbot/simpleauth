package models

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func TestOptionsValue(t *testing.T) {
	var o *Options
	actual, err := o.Value()
	require.Nil(t, err)
	require.Nil(t, actual)

	o = new(Options)
	expected := "null"
	actual, err = o.Value()
	require.Nil(t, err)
	require.Equal(t, expected, actual)

	o = &Options{
		"hello":    "world",
		"not":      "today",
		"paradise": "lost",
	}
	expected = "{\"hello\":\"world\",\"not\":\"today\",\"paradise\":\"lost\"}"
	actual, err = o.Value()
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestOptionsScan(t *testing.T) {
	val := "{\"hello\":\"world\",\"not\":\"today\",\"paradise\":\"lost\"}"
	valB := []byte(val)
	key := "hello"
	expected := "world"
	o := new(Options)

	err := o.Scan(nil)
	require.Nil(t, err)
	require.Equal(t, 0, len(*o))

	err = o.Scan(valB)
	require.Nil(t, err)
	require.Equal(t, expected, (*o)[key])
}

func TestOptionsMarshalJSON(t *testing.T) {
	o := new(Options)
	expected := []byte("null")
	actual, err := o.MarshalJSON()
	require.Nil(t, err)
	require.Equal(t, expected, actual)

	o = &Options{
		"hello":    "world",
		"not":      "today",
		"paradise": "lost",
	}
	expected = []byte("{\"hello\":\"world\",\"not\":\"today\",\"paradise\":\"lost\"}")
	actual, err = o.MarshalJSON()
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestOptionsUnmarshalJSON(t *testing.T) {
	val := "{\"hello\":\"world\",\"not\":\"today\",\"paradise\":\"lost\"}"
	valB := []byte(val)
	key := "hello"
	expected := "world"

	o := new(Options)
	err := o.UnmarshalJSON(valB)
	require.Nil(t, err)
	require.Equal(t, expected, (*o)[key])
}

func TestOptionsGormDataType(t *testing.T) {
	require.Equal(t, "options", (Options{}).GormDataType())
}

func TestOptionsDBDataType(t *testing.T) {
	db := new(gorm.DB)
	db.Config = new(gorm.Config)
	tests := []struct {
		Dialect  gorm.Dialector
		Expected string
	}{
		{sqlite.Dialector{}, "JSON"},
		{mysql.Dialector{}, "JSON"},
		{postgres.Dialector{}, "JSONB"},
		{sqlserver.Dialector{}, "NVARCHAR(MAX)"},
	}
	for _, test := range tests {
		db.Config.Dialector = test.Dialect
		actual := (Options{}).GormDBDataType(db, nil)
		require.Equal(t, test.Expected, actual)
	}
}

func TestOptionsGormValue(t *testing.T) {
	o := &Options{
		"hello":    "world",
		"not":      "today",
		"paradise": "lost",
	}
	data, err := o.MarshalJSON()
	require.Nil(t, err)
	tests := []struct {
		Dialect  gorm.Dialector
		Expected clause.Expr
	}{
		{
			Dialect:  sqlite.Dialector{},
			Expected: clause.Expr{SQL: "?", Vars: []interface{}{string(data)}},
		}, {
			Dialect: mysql.Dialector{
				Config: &mysql.Config{ServerVersion: "MariaDB"},
			},
			Expected: clause.Expr{SQL: "?", Vars: []interface{}{string(data)}},
		}, {
			Dialect: mysql.Dialector{
				Config: &mysql.Config{ServerVersion: "NotMariaDB"},
			},
			Expected: clause.Expr{SQL: "?", Vars: []interface{}{string(data)}},
		}, {
			Dialect:  postgres.Dialector{},
			Expected: clause.Expr{SQL: "?", Vars: []interface{}{string(data)}},
		}, {
			Dialect:  sqlserver.Dialector{},
			Expected: clause.Expr{SQL: "?", Vars: []interface{}{string(data)}},
		},
	}
	ctx := context.Background()
	db := new(gorm.DB)
	db.Config = new(gorm.Config)
	for _, test := range tests {
		db.Config.Dialector = test.Dialect
		actual := (*o).GormValue(ctx, db)
		require.Equal(t, test.Expected, actual)
	}
}

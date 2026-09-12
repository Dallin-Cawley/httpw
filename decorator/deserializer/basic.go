package deserializer

import (
	"encoding"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
)

// BasicDeserializer is a generic deserializer implementing Deserializer[T].
// It attempts to deserialize bytes into T using various unmarshaler interfaces
// (json.Unmarshaler, encoding.TextUnmarshaler, encoding.BinaryUnmarshaler, xml.Unmarshaler).
type BasicDeserializer[T any] struct{}

// NewBasicDeserializer creates a new BasicDeserializer instance.
func NewBasicDeserializer[T any]() *BasicDeserializer[T] {
	return &BasicDeserializer[T]{}
}

// Deserialize attempts to unmarshal the given data into type T using available unmarshaler interfaces.
func (d *BasicDeserializer[T]) Deserialize(data []byte) (T, error) {
	var errs []error

	// 1. json.Unmarshaler
	{
		targetPtr := createTarget[T]()
		if jsonUnmarshaler, ok := targetPtr.(json.Unmarshaler); ok {
			if err := jsonUnmarshaler.UnmarshalJSON(data); err == nil {
				return getResult[T](targetPtr), nil
			} else {
				errs = append(errs, err)
			}
		}
	}

	// 2. encoding.TextUnmarshaler
	{
		targetPtr := createTarget[T]()
		if textUnmarshaler, ok := targetPtr.(encoding.TextUnmarshaler); ok {
			if err := textUnmarshaler.UnmarshalText(data); err == nil {
				return getResult[T](targetPtr), nil
			} else {
				errs = append(errs, err)
			}
		}
	}

	// 3. encoding.BinaryUnmarshaler
	{
		targetPtr := createTarget[T]()
		if binaryUnmarshaler, ok := targetPtr.(encoding.BinaryUnmarshaler); ok {
			if err := binaryUnmarshaler.UnmarshalBinary(data); err == nil {
				return getResult[T](targetPtr), nil
			} else {
				errs = append(errs, err)
			}
		}
	}

	// 4. xml.Unmarshaler
	{
		targetPtr := createTarget[T]()
		if _, ok := targetPtr.(xml.Unmarshaler); ok {
			if err := xml.Unmarshal(data, targetPtr); err == nil {
				return getResult[T](targetPtr), nil
			} else {
				errs = append(errs, err)
			}
		}
	}

	return *new(T), fmt.Errorf("failed to deserialize data: %w", errors.Join(errs...))
}

func createTarget[T any]() any {
	var target T
	targetVal := reflect.ValueOf(&target).Elem()

	if targetVal.Kind() == reflect.Pointer {
		val := targetVal
		for val.Kind() == reflect.Pointer {
			newElem := reflect.New(val.Type().Elem())
			val.Set(newElem)
			val = val.Elem()
		}

		return target
	}

	return &target
}

func getResult[T any](targetPtr any) T {
	if ptr, ok := targetPtr.(*T); ok {
		return *ptr
	}

	return targetPtr.(T)
}

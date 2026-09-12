package loader

type Loader[T any] interface {
	Load() (T, error)
}

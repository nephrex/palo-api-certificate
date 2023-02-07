package main

func main() {

	cert, key := getCert("changeme", "fake@email.com", []string{"testdomain"})

	println(cert)
	println(key)
}

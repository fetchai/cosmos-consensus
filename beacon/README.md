Build c++ library:
```bash
cd beacon_cpp
rm -Rf build
mkdir build
cd build
cmake ..
make
cp lib/libmcl.a libs/libmcl.a
```

Now build and run tests from beacon directory
```bash
go clean -cache
go test
```


To build the trusted dealer:
```bash
cd beacon/beacon_cpp && \
	rm -Rf build && \
	mkdir build && \
	cd build && \
	cmake ../.. && \ 
	make TrustedDealer && \ 
	cd ../..
```

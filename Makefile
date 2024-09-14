INCLUDES=-Iquiche/quiche/include -I/usr/local/include
LIBS=quiche/target/release/libquiche.a -lev -ldl -pthread -lm

main: quiche-client.c
	gcc -o main $< $(LIBS) $(INCLUDES) -g

quiche:
	git clone https://github.com/cloudflare/quiche.git

	cd quiche && \
		git submodule update --init && \
		cargo build --features ffi --release

libev:
	curl -O http://dist.schmorp.de/libev/libev-4.33.tar.gz
	tar -xvf libev-4.33.tar.gz
	rm libev-4.33.tar.gz
	mv libev-4.33 libev

	cd libev && \
		./configure && \
		make && \
		sudo make install
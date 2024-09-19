INCLUDES=-Iquiche/quiche/include -I/usr/local/include -Iuthash/include
LIBS=quiche/target/release/libquiche.a -lev -ldl -pthread -lm

all: client server

server: quiche-server.c dependencies
	gcc -o server $< $(LIBS) $(INCLUDES) -g

client: quiche-client.c dependencies
	gcc -o client $< $(LIBS) $(INCLUDES) -g

dependencies: quiche libev uthash

quiche:
	git clone https://github.com/cloudflare/quiche.git

	cd quiche && \
		git submodule update --init && \
		cargo build --features ffi --features qlog --release

libev:
	curl -O http://dist.schmorp.de/libev/libev-4.33.tar.gz
	tar -xvf libev-4.33.tar.gz
	rm libev-4.33.tar.gz
	mv libev-4.33 libev

	cd libev && \
		./configure && \
		make && \
		sudo make install

uthash:
	curl -LO https://github.com/troydhanson/uthash/archive/refs/tags/v2.3.0.tar.gz
	tar -xvf v2.3.0.tar.gz
	mv uthash-2.3.0 uthash

clean:
	rm client
	rm server
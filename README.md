## Example Usage

```bash 
make

# launch server
./server localhost 8000 2> server.out &
pid=$!  # to shutdown later

# ./client host port path, output is saved in out.html
./client localhost 8080 /big.txt 2> client.out
``` 
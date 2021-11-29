source_files := $(shell find prog/ -name *.c)
object_files := $(patsubst prog/%.c, build/obj/%.o, $(source_files))

$(object_files): build/obj/%.o : prog/%.c
	mkdir -p $(dir $@) && \
	gcc -c -I prog/intf $(patsubst build/obj/%.o, prog/%.c, $@) -o $@

.PHONY: build
build: $(object_files)
	gcc -o build/prog $(object_files) -lmenu -lpanel -lncurses -lpcap -lpthread -O3

debug: $(object_files)
	gcc -o build/prog $(object_files) -lmenu -lpanel -lncurses -lpcap -lpthread -ggdb
	
clean: 
	rm -rf build

run:
	./build/prog
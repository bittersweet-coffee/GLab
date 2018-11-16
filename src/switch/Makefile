programs = parser hub switch vswitch arp router

all: $(programs)

$(programs): %: %.c
	gcc -g -O0 -Wall -fwrapv -fPIE -Wstack-protector -fstack-protector-all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 --param ssp-buffer-size=1 -pie -z relro -z now -fsanitize=address,undefined -fno-omit-frame-pointer $< -o $@

clean:
	rm -f $(programs)

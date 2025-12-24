LIBMAST1C0RE=$(MAST1C0RE)/sdk

# Addresses
TEXT	?= 0x1300000
DATA	?= 0x1110000
ABI		?= 0x1100000

# Variables
SYSTEM          ?= PS4
FIRMWARE        ?= 0.00
EBOOT_VERSION   ?= 1.01

FIRMWARE_UNDER  =  $(subst .,_,$(FIRMWARE))
FIRMWARE_DASH   =  $(subst .,-,$(FIRMWARE))
FIRMWARE_NUM    =  $(subst .,,$(FIRMWARE))
EBOOT_NUM       =  $(subst .,,$(EBOOT_VERSION))

# Binaries
PREFIX			= mips64r5900el-ps2-elf-
CPP				= $(PREFIX)g++
SAVE_EXPLOIT	?= okrager

# Directories
BDIR = bin
ODIR = build
SDIR = src
OUT = $(BDIR)/$(SYSTEM)-$(FIRMWARE_DASH)

# Files
CPPFILES	= $(wildcard $(SDIR)/*.cpp $(SDIR)/*/*.cpp)
OBJS		= $(patsubst $(SDIR)/%.cpp, $(ODIR)/%.o, $(CPPFILES))

# Save files
SAVE_IN		?= $(BDIR)/clean/VMC0.card
SAVE_OUT	?= $(OUT)/VMC0.card

# Embedded payload
PAYLOAD_TMP  = payload.bin # Used in payload.S
PAYLOAD_S    = payload.S
PAYLOAD_OBJ  = $(ODIR)/payload.o

# Flags
LINKFLAGS	= -Wl,-z,max-page-size=0x1,--section-start=.MIPS.abiflags=$(ABI)
CPPFLAGS	= -Tdata=$(DATA) -Ttext=$(TEXT) -mno-gpopt -nostartfiles -nostdlib -nodefaultlibs -ffreestanding $(LINKFLAGS) -I$(LIBMAST1C0RE)/include -I. -D$(SYSTEM)=1 -DFIRMWARE=$(FIRMWARE_NUM) -DEBOOT_VERSION=$(EBOOT_NUM) -Wno-error=jump-misses-init

# Target
TARGET = $(OUT)/laps3c0re-$(SYSTEM)-$(FIRMWARE_DASH).elf

all: compile save

save:
	$(SAVE_EXPLOIT) $(SAVE_IN) $(SAVE_OUT) $(TARGET)

compile: sdk $(ODIR) $(OBJS) crt0 $(OUT) $(PAYLOAD_OBJ)
	$(CPP) $(CPPFLAGS) $(ODIR)/crt0.o $(PAYLOAD_OBJ) $(OBJS) -L$(LIBMAST1C0RE) -l:mast1c0re.a -o $(TARGET)

sdk:
	make -B -C $(LIBMAST1C0RE) SYSTEM=$(SYSTEM) FIRMWARE=$(FIRMWARE_NUM) EBOOT=$(EBOOT_NUM) clean
	make -B -C $(LIBMAST1C0RE) SYSTEM=$(SYSTEM) FIRMWARE=$(FIRMWARE_NUM) EBOOT=$(EBOOT_NUM)

crt0:
	$(CPP) $(CPPFLAGS) -c $(LIBMAST1C0RE)/crt0.S -o $(ODIR)/crt0.o

$(PAYLOAD_OBJ): $(PAYLOAD_S)
	-@echo "" > $(PAYLOAD_TMP)
	-@cp $(PAYLOAD) $(PAYLOAD_TMP) 2>/dev/null || true
	$(CPP) -c -o $@ $< $(CPPFLAGS)
	-@rm -f $(PAYLOAD_TMP)

$(ODIR)/%.o: $(SDIR)/%.cpp
	@mkdir -p $(shell dirname $@)
	$(CPP) -c -o $@ $< $(CPPFLAGS)

$(ODIR) $(OUT):
	@mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(ODIR)

.PHONY: clean_all
clean_all:
	rm -rf $(ODIR) $(BDIR)/PS4-* $(BDIR)/PS5-*

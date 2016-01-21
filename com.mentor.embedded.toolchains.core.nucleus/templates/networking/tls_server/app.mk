export TOOLSETS_HOME=$(SYSTEM_DIR)/bsp/$(PLATFORM)/toolset

# Check to see is and USER_CONFIG was used to build the system library else default to "debug"
ifeq ($(USER_CONFIG),)
APP_CONFIG=debug
else
APP_CONFIG=$(basename $(notdir $(USER_CONFIG)))
endif
include $(SYSTEM_DIR)/output/$(TOOLSET)/$(PLATFORM)/$(APP_CONFIG)/system.properties

RM := rm -rf

comma :=,
empty :=
space := $(empty) $(empty)

# Fixes up the depedency files to include the dependency file itself
# in the rule target.  This way the dependency files will be rebuilt
# when header files change.
#
# NOTE: The dependency file that is being fixed up is deleted if it gets
#       fixed up successfully.
#
# $(1) - the dependency file to fixup.
# $(2) - the output filename for the fixed dependency file.

ifeq ($(TOOLSET),rvct)
define fixup-deps
sed -e "s,[\],/,g" -e "s,\(.*$(notdir $(basename $(2)))\)\.o[ :]*,\1\.o:,g" -e "s, ,\\ ,g" -e "s,\(.*$(notdir $(basename $(2)))\)\.o[ :]*,$(2:.d=.o) $(2) : ,g" $(1) > $(2) \
&& $(RM) $(1)
endef
else
define fixup-deps
sed -e "s,[\]\([^ ]\),/\1,g" -e "s,\(.*$(notdir $(basename $(2)))\)\.o[ :]*,\1\.o \1\.d:,g" $(1) > $(2) \
&& $(RM) $(1)
endef
endif

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
tls_server.c 

OBJS += \
tls_server.o 

# Include the generated dependencies.
ifneq ($(wildcard $(OBJS:.o=.d)),)
ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:.o=.d)
endif
endif

ProjName := tls_server
EXECUTABLE := $(ProjName).out

all: $(EXECUTABLE)

$(EXECUTABLE) : $(OBJS) $(NUCLEUS_LIB)
	@echo 'Building file: $@'
	@echo 'Invoking Linker'
	$(call link,$@,$^)
ifneq ($(RAWBINARY),0)
	@echo 'Building file: $(basename $@).bin'
	@echo 'Invoking Post Linker'
	$(call postlink,$@)
endif

%.o: %.c

	@echo 'Building file: $<'
	@echo 'Invoking C Compiler'
	$(call compile,$<,$@)
	@$(call fixup-deps,$(@:.o=.d.tmp),$(@:.o=.d))
	@echo 'Finished building: $<'
	@echo ' '

clean:
	-$(RM) $(OBJS) $(OBJS:.o=.d) $(EXECUTABLE) $(ProjName).map $(ProjName).bin
	-@echo ' '

.PHONY: all clean


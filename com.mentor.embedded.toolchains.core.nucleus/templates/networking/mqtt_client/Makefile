export SYSTEM_DIR=../../../../nucleus
export USER_CONFIG=samples/networking/mqtt_client/mqtt_client.config

all: 
	$(MAKE) -C "$(SYSTEM_DIR)" distclean
	$(MAKE) -C "$(SYSTEM_DIR)" all

	@echo Building application...
	$(MAKE) -f app.mk all

clean:
	$(MAKE) -C "$(SYSTEM_DIR)" clean
	$(MAKE) -f app.mk clean
	-@echo ' '

.PHONY: all clean

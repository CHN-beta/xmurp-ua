include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
 
PKG_NAME:=xmurp-ua
PKG_RELEASE:=15
 
include $(INCLUDE_DIR)/package.mk

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \

MAKE_OPTS:=$(KERNEL_MAKE_FLAGS) \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	CONFIG_xmurp-ua=m

define KernelPackage/xmurp-ua
	SUBMENU:=Other modules
	TITLE:=xmurp-ua
	FILES:=$(PKG_BUILD_DIR)/xmurp-ua.ko
	AUTOLOAD:=$(call AutoLoad,99,xmurp-ua)
	KCONFIG:=
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" $(MAKE_OPTS) modules
endef

$(eval $(call KernelPackage,xmurp-ua))
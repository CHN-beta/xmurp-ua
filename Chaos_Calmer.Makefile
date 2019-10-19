include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=xmurp-ua
PKG_RELEASE:=31

include $(INCLUDE_DIR)/package.mk

define KernelPackage/xmurp-ua
  SUBMENU:=Other modules
  TITLE:=XMURP UA
  FILES:=$(PKG_BUILD_DIR)/xmurp-ua.ko
  AUTOLOAD:=$(call AutoLoad,99,xmurp-ua,1)
endef

define KernelPackage/xmurp-ua/description
  Modify UA in HTTP for anti-detection of router in XMU.
endef

EXTRA_KCONFIG:= \
	CONFIG_XMURP_UA=m

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,xmurp-ua))

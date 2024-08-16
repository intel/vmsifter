project('injector', 'c',
  version : '1.0',
  default_options : ['warning_level=2', 'werror=true', 'strip=true', 'buildtype=release', 'b_pie=true'])

glib = dependency('glib-2.0')
libvmi = dependency('libvmi')
libxc = dependency('xencontrol')
libxl = dependency('xenlight')

add_project_arguments('-Wno-address-of-packed-member', language: 'c')
# canaries
add_project_arguments('-fstack-protector-strong', language: 'c')
# fortify
add_project_arguments('-D_FORTIFY_SOURCE=2', language: 'c')
# full RELRO
add_project_link_arguments('-Wl,-z,relro,-z,now', language: 'c')

executable('injector',
           'src/main.c',
           'src/private.c',
           'src/forkvm.c',
           'src/signal.c',
           'src/vmi.c',
           dependencies : [ libxc, libxl, glib, libvmi ],
           install : true)

project(
	'simple_notif_daemon',
	'c',
	version: '1.0.0',
	license: 'MIT',
	meson_version: '>=0.60.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
)

add_project_arguments([
	'-Wundef',

	'-Wno-unused-parameter',
	'-Wno-missing-braces',
], language: 'c')

cc = meson.get_compiler('c')

if get_option('sd-bus-provider') == 'auto'
	assert(get_option('auto_features').auto(), 'sd-bus-provider must not be set to auto since auto_features != auto')
	sdbus = dependency('libsystemd', 'libelogind', 'basu')
else
	sdbus = dependency(get_option('sd-bus-provider'))
endif
add_project_arguments('-DHAVE_' + sdbus.name().to_upper() + '=1', language: 'c')

src_files = [
    'main.c',
]

executable(
	'simple_notif_daemon',
	files(src_files),
	dependencies: [
		sdbus,
	],
	install: true,
)

conf_data = configuration_data()
conf_data.set('bindir', get_option('prefix') / get_option('bindir'))

configure_file(
	configuration: conf_data,
	input: 'es.froggi.simple_notif_daemon.service.in',
	output: '@BASENAME@',
	install_dir: get_option('datadir') + '/dbus-1/services',
)

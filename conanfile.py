from conan import ConanFile
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class VeyronSdkConan(ConanFile):
    name = "veyron-sdk-cpp"
    version = "0.1.0"
    description = (
        "C++ SDK for writing Veyron plugins - async IPC client, Plugin "
        "interface, and the Veyron wire protocol (framing, zstd compression, "
        "HMAC frame MACs)."
    )
    license = "MIT"
    url = "https://github.com/veyron-core/vynkor"
    homepage = "https://github.com/veyron-core/vynkor"
    topics = ("veyron", "plugin", "ipc", "sdk", "kernel")

    package_type = "static-library"
    settings = "os", "arch", "compiler", "build_type"
    options = {"fPIC": [True, False]}
    default_options = {"fPIC": True}

    exports_sources = "CMakeLists.txt", "proto/*", "src/*", "include/*", "tests/*", "examples/*"

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def validate(self):
        check_min_cppstd(self, 17)

    def requirements(self):
        self.requires("protobuf/5.29.6", transitive_headers=True, transitive_libs=True)
        self.requires("openssl/3.5.7")
        self.requires("zstd/1.5.7")

    def build_requirements(self):
        # protoc must run on the build machine; pin it to the same version
        # as the host protobuf requirement so generated code matches the lib.
        self.tool_requires("protobuf/<host_version>")
        self.test_requires("gtest/1.14.0")

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if not self.conf.get("tools.build:skip_test", default=False):
            cmake.test()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "veyron-sdk")
        self.cpp_info.set_property("cmake_target_name", "veyron::sdk")
        self.cpp_info.libs = ["veyron_sdk_cpp"]
        self.cpp_info.requires = [
            "protobuf::libprotobuf",
            "openssl::openssl",
            "zstd::libzstd_static",
        ]
        if self.settings.os in ("Linux", "FreeBSD"):
            self.cpp_info.system_libs = ["pthread"]

import os
import subprocess
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py

def build_sandpip_so():
    os.makedirs("sandpip", exist_ok=True)
    # Сборка библиотеки v1.0
    cmd1 = ["gcc", "-O2", "-Wall", "-Wextra", "-fPIC", "-shared", "-ldl", "-o", "sandpip/sandpip.so", "src/sandpip.c"]
    print("Compiling sandpip.so:", " ".join(cmd1))
    subprocess.check_call(cmd1)
    # Сборка лаунчера v2.0
    cmd2 = ["gcc", "-O2", "-Wall", "-Wextra", "-o", "sandpip/sandpip_v2_launcher", "src/sandpip_v2.c"]
    print("Compiling sandpip_v2_launcher:", " ".join(cmd2))
    subprocess.check_call(cmd2)

class CustomBuildPy(build_py):
    def run(self):
        build_sandpip_so()
        super().run()

setup(
    packages=find_packages(),
    cmdclass={
        "build_py": CustomBuildPy,
    },
    package_data={
        "sandpip": ["sandpip.so", "sandpip_v2_launcher"],
    },
)

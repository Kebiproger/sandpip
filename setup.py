import os
import subprocess
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py

def build_sandpip_so():
    os.makedirs("sandpip", exist_ok=True)
    cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-fPIC", "-shared", "-ldl", "-o", "sandpip/sandpip.so", "src/sandpip.c"]
    print("Compiling sandpip.so:", " ".join(cmd))
    subprocess.check_call(cmd)

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
        "sandpip": ["sandpip.so"],
    },
)

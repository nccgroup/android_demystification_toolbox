import setuptools

setuptools.setup(
  name='adt',
  version='0.1',
  description='Android Demystification Toolbox',
  url='https://github.com/nccgroup/android_demystification_toolbox',
  author='Nicolas Guigo',
  author_email='nicolas.guigo@nccgroup.com',
  packages=setuptools.find_packages(),
  zip_safe=False,
  install_requires=[
      'miasm',
    ],
)

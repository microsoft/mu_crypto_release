============================
Mu Crypto Release Repository
============================

This project builds the Project Mu shared crypto binaries. It consists of scripts, pipelines, and submodules to perform
a binary release of EDK II [`CryptoPkg`](https://github.com/microsoft/mu_basecore/tree/HEAD/CryptoPkg)
drivers to power the `BaseCryptOnProtocol/Ppi` infrastructure.

These releases will be tagged and tracked in this repo, but published to the Mu Nuget feed.

This repository is part of Project Mu. Please see Project Mu for details https://microsoft.github.io/mu


Using Shared Crypto
===================

If you simply want to use shared crypto in your project, view the [shared crypto driver instructions](CryptoBinPkg/Driver/readme.md).

The remaining instructions are for those working directly in this repository to build new shared crypto releases.


Repo Scripts
============

Here is a brief description of the scripts in this repository and how they are used.


CommonBuildSettings.py
----------------------

This script is not to be used directly, but is a configuration module to be consumed by the other scripts
in this repo (or used directly as a Stuart settings module). If any submodules or scopes need to be changed,
this is the place to do it.

Note that any changes to names might require additional changes in other scripts that look for those names
when copying files around.


SingleFlavorBuild.py
--------------------

This script will run an EDK2 build of a single flavor and a single target of CryptBin. Example: ``TINY_SHA,DEBUG`` or
``STANDARD,RELEASE``. This is because a single EDK2 build run requires a single and flavor target and so each run
must be set up independently. This script is called multiple times by the ``MultiFlavorBuild.py`` script.

Should have good support for ``-h`` and print a useful help menu.


MultiFlavorBuild.py
-------------------

This script organizes the build for an entire release by coordinating multiple calls to ``SingleFlavorBuild.py``.
Multiple targets, flavors, and architectures can be passed into this script to be built in sequence. This is the
main entry point for the build from the pipeline and is the ideal entry point for any local builds.

Calling this script without any parameters default to all available targets, architectures, and flavors.

Should have good support for ``-h`` and print a useful help menu.


AssembleNugetPackage.py
-----------------------

This script will take in a directory of build artifacts and reorganize them into the Nuget package layout.

Should have good support for ``-h`` and print a useful help menu.


Building on a Local Dev System
==============================

Building locally for test consists of two primary pieces:

- Run the ``MultiFlavorBuild.py`` script to build the drivers, depexes, and other release collateral.
- Run the ``AssembleNugetPackage.py`` script to organize the release collateral into the format for
   the release package. Just point at the ``Build`` directory as the input directory.

The steps are:

1) Make sure that you've updated your pip requirements
2) Run the ``MultiFlavorBuild.py`` script with ``--setup``
3) Run the ``MultiFlavorBuild.py`` script with ``--update``
4) Run the ``MultiFlavorBuild.py`` script with whatever flavors and architectures you would like in
   your binary package. This is the primary build and may take a while
5) Run the ``MultiFlavorBuild.py`` script with ``--bundle`` to create the Nuget package layout
   in the ``Bundle`` directory


Building OpensslPkg
===================

``OpensslPkg`` is built using normal Stuart build commands. The package, target, and architecture are specified as
parameters to ``.pytool/CISettings.py``.

Example to build the ``DEBUG`` target for the ``X64`` architecture:

``> stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t DEBUG -a X64 TOOL_CHAIN_TAG=VS2022``

Note that the ``OpensslPkg`` build is not required to build the crypto binaries only to build and verify CI checks
against the code in the package.


Releasing a Pipeline Build
==========================

TODO: How to support the security patch repos? (This isn't essential if there are no security
      patches for CryptoPkg, but it's a necessary piece to figure out for the process.)

Most releases will be performed on a new EDK2 integration cycle (to re-enable the CryptoBin
dependencies for the Basecore release branch). As such, most integrations will need all of
the following steps.

If you're already on an existing release branch and you've just updated CryptoPkg and want
to release a new CryptoBin, you can skip to the `Regular Release Steps`_.


First Steps (for a new integration)
-----------------------------------

While performing the Basecore integration:

1) Disable the ``edk2-basecrypto-driver-bin`` extdep until a new release can be generated for
   this integration

   - In the file ``CryptoPkg/Driver/Bin/BaseCryptoDriver_ext_dep.json``:
   - Set the ``scope`` to "global-disabled"
   - Set the ``version`` back to "0.0.0" (for safety so that we don't accidentally
     mis-version it when re-enabling)

Then, in this repo:

1) Take a look at the ``.gitmodules`` file and cross reference all required submodules

   - Make sure that all submodules have a matching ``release/*`` branch and that they
     have all been tagged as ``*_CIBuild``
   - Example: if we're trying to make a new package on the ``release/202202`` branch, we
     must first check `Basecore <https://github.com/microsoft/mu_basecore.git>`_ and
     `Silicon Arm Tiano <https://github.com/microsoft/mu_silicon_arm_tiano.git>`_ to make
     sure that they have ``2202_CIBuild`` tags, proving that they're valid to perform a new
     release

2) Create the new release branch in this repo
3) Update the ``version_major_minor`` parameter in the ``.azuredevops/pipelines/ReleaseBuild.yml`` file
4) Update ``pip-requirements.txt`` file to match Basecore for this release
5) Update pipeline tools to match Basecore for the new release (right now, this is just
   the ``python_version`` variable)


Regular Release Steps
---------------------

In this repo:

.. _generate-packaging-files:

1) Update to the correct release branches for each submodule in ``.gitmodules``
2) Pull the correct commit for each submodule
3) Determine whether any configuration or PCDs need to change. This configuration is outside the
   scope of this document. Please refer to the greater documentation around CryptoBin and BCOP
4) Generate the new packaging files. These files are created by a script that lives in Mu Crypto Release

   - Script lives at ``CryptoBinPkg/Driver/Packaging/generate_cryptodriver.py``
   - Running this with no arguments should be an acceptable default. Refer to the script help
     for information on the possible arguments
   - This script needs to be executed from within a valid Python venv configured for Mu

5) Compare the changes and stage them for PR into Mu Crypto Release

   - Total changes should affect dozens of files in CryptoBinPkg, most of which live in ``CryptoBinPkg/Driver/Bin``
     directory
   - For *most* releases, these changes should only be timestamps. If they are anything other than timestamps,
     make sure you understand why and make sure they are intended
   - **IMPORTANT NOTE** If *any* new functions are introduced or any existing crypto family is updated
     to include new functions (or the prototypes change), you must update the ``EDKII_CRYPTO_VERSION``
     in ``CryptoBinPkg/Driver/Packaging/Crypto.template.h``

6) Submit your PR to Mu Crypto Release

Once the server is updated for the new release, run the release pipeline on the new branch. The release
pipeline is located in the public Project Mu DevOps organization. To release a new version:

1) Go to `the release pipeline <https://dev.azure.com/projectmu/mu/_build?definitionId=97>`_
2) ``Run pipeline`` and select your branch
3) The following parameters are currently available:
    a) If you're confident in this build, you can go ahead and click the "Publish Nuget Package"
       checkbox
    b) It's possible to swap the VM image and build toolchain to Linux/GCC5
    c) The Major and Minor version is set by default in the pipeline (updated on each release), but
       can be overridden
    d) The Patch version must be set on each release. This must be manually checked for uniqueness.
       See `here <https://dev.azure.com/projectmu/mu/_packaging?_a=package&feed=Mu-Public&package=edk2-basecrypto-driver-bin&protocolType=NuGet&version=2021.11.2&view=versions>`_
       for the currently published versions
    e) The Version Label is optional. For example, a Version Label might be ``-beta`` for version
       ``X.Y.Z-beta``. If you don't want a version label at all, set this to ``None`` and the pipeline
       will ignore it entirely

Once successfully released, tag the commit with the version (e.g. ``2022.02.1``) and push tag to the server.


Code of Conduct
===============

This project has adopted the Microsoft Open Source Code of Conduct https://opensource.microsoft.com/codeofconduct/

For more information see the Code of Conduct FAQ https://opensource.microsoft.com/codeofconduct/faq/
or contact `opencode@microsoft.com <mailto:opencode@microsoft.com>`_. with any additional questions or comments.


Contributions
=============

Contributions are always welcome and encouraged!
Please open any issues in the Project Mu GitHub tracker and read https://microsoft.github.io/mu/How/contributing/


Copyright & License
===================

| Copyright (C) Microsoft Corporation
| SPDX-License-Identifier: BSD-2-Clause-Patent

import glob
import os

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import read_file, write_to_file

from yunohost.tools import (
    Migration,
    tools_update,
)
from yunohost.app import unstable_apps
from yunohost.regenconf import manually_modified_files
from yunohost.utils.system import (
    free_space_in_directory,
    get_ynh_package_version,
    _list_upgradable_apt_packages,
    aptitude_with_progress_bar,
)

# getActionLogger is not there in bookworm,
# we use this try/except to make it agnostic wether or not we're on 11.x or 12.x
# otherwise this may trigger stupid issues
try:
    from moulinette.utils.log import getActionLogger
    logger = getActionLogger("yunohost.migration")
except ImportError:
    import logging
    logger = logging.getLogger("yunohost.migration")


N_CURRENT_DEBIAN = 11
N_CURRENT_YUNOHOST = 11

VENV_REQUIREMENTS_SUFFIX = ".requirements_backup_for_bookworm_upgrade.txt"


def _get_all_venvs(dir, level=0, maxlevel=3):
    """
    Returns the list of all python virtual env directories recursively

    Arguments:
        dir - the directory to scan in
        maxlevel - the depth of the recursion
        level - do not edit this, used as an iterator
    """
    if not os.path.exists(dir):
        return []

    result = []
    # Using os functions instead of glob, because glob doesn't support hidden folders, and we need recursion with a fixed depth
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isdir(path):
            activatepath = os.path.join(path, "bin", "activate")
            if os.path.isfile(activatepath):
                content = read_file(activatepath)
                if ("VIRTUAL_ENV" in content) and ("PYTHONHOME" in content):
                    result.append(path)
                    continue
            if level < maxlevel:
                result += _get_all_venvs(path, level=level + 1)
    return result


def _backup_pip_freeze_for_python_app_venvs():
    """
    Generate a requirements file for all python virtual env located inside /opt/ and /var/www/
    """

    venvs = _get_all_venvs("/opt/") + _get_all_venvs("/var/www/")
    for venv in venvs:
        # Generate a requirements file from venv
        os.system(
            f"{venv}/bin/pip freeze > {venv}{VENV_REQUIREMENTS_SUFFIX} 2>/dev/null"
        )


class MyMigration(Migration):
    "Upgrade the system to Debian Bookworm and Yunohost 12.x"

    mode = "manual"

    def run(self):
        self.check_assertions()

        logger.info(m18n.n("migration_0027_start"))

        #
        # Add new apt .deb signing key
        #

        new_apt_key = "https://forge.yunohost.org/yunohost_bookworm.asc"
        os.system(f'wget --timeout 900 --quiet "{new_apt_key}" --output-document=- | gpg --dearmor >"/usr/share/keyrings/yunohost-bookworm.gpg"')

        # Add Sury key even if extra_php_version.list was already there,
        # because some old system may be using an outdated key not valid for Bookworm
        # and that'll block the migration
        os.system(
            'wget --timeout 900 --quiet "https://packages.sury.org/php/apt.gpg" --output-document=- | gpg --dearmor >"/etc/apt/trusted.gpg.d/extra_php_version.gpg"'
        )

        #
        # Patch sources.list
        #

        logger.info(m18n.n("migration_0027_patching_sources_list"))
        self.patch_apt_sources_list()

        #
        # Get requirements of the different venvs from python apps
        #

        _backup_pip_freeze_for_python_app_venvs()

        #
        # Run apt update
        #

        aptitude_with_progress_bar("update")

        # Tell libc6 it's okay to restart system stuff during the upgrade
        os.system(
            "echo 'libc6 libraries/restart-without-asking boolean true' | debconf-set-selections"
        )

        # Do not restart nginx during the upgrade of nginx-common and nginx-extras ...
        # c.f. https://manpages.debian.org/bullseye/init-system-helpers/deb-systemd-invoke.1p.en.html
        # and zcat /usr/share/doc/init-system-helpers/README.policy-rc.d.gz
        # and the code inside /usr/bin/deb-systemd-invoke to see how it calls /usr/sbin/policy-rc.d ...
        # and also invoke-rc.d ...
        write_to_file(
            "/usr/sbin/policy-rc.d",
            '#!/bin/bash\n[[ "$1" =~ "nginx" ]] && exit 101 || exit 0',
        )
        os.system("chmod +x /usr/sbin/policy-rc.d")

        # Don't send an email to root about the postgresql migration. It should be handled automatically after.
        os.system(
            "echo 'postgresql-common postgresql-common/obsolete-major seen true' | debconf-set-selections"
        )

        #
        # Patch yunohost conflicts
        #
        logger.info(m18n.n("migration_0027_patch_yunohost_conflicts"))

        self.patch_yunohost_conflicts()

        #
        # Critical fix for RPI otherwise network is down after rebooting
        # https://forum.yunohost.org/t/20652
        #
        # FIXME : this is from buster->bullseye, do we still needed it ?
        #
        #if os.system("systemctl | grep -q dhcpcd") == 0:
        #    logger.info("Applying fix for DHCPCD ...")
        #    os.system("mkdir -p /etc/systemd/system/dhcpcd.service.d")
        #    write_to_file(
        #        "/etc/systemd/system/dhcpcd.service.d/wait.conf",
        #        "[Service]\nExecStart=\nExecStart=/usr/sbin/dhcpcd -w",
        #    )

        #
        # Main upgrade
        #
        logger.info(m18n.n("migration_0027_main_upgrade"))

        # Mark php, mariadb, metronome and rspamd as "auto" so that they may be uninstalled if they ain't explicitly wanted by app or admins
        php_packages = self.get_php_packages()
        aptitude_with_progress_bar(f"markauto mariadb-server metronome rspamd {' '.join(php_packages)}")

        # Hold import yunohost packages
        apps_packages = self.get_apps_equivs_packages()
        aptitude_with_progress_bar(f"hold yunohost moulinette ssowat yunohost-admin {' '.join(apps_packages)}")

        aptitude_with_progress_bar("upgrade cron --show-why -y -o APT::Force-LoopBreak=1 -o Dpkg::Options::='--force-confold'")

        # FIXME : find a way to simulate and validate the upgrade first
        aptitude_with_progress_bar("full-upgrade --show-why -y -o Dpkg::Options::='--force-confold'")

        if self.debian_major_version() == N_CURRENT_DEBIAN:
            raise YunohostError("migration_0027_still_on_buster_after_main_upgrade")

        # Clean the mess
        logger.info(m18n.n("migration_0027_cleaning_up"))
        os.system(
            "LC_ALL=C DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt autoremove --assume-yes"
        )
        os.system("apt clean --assume-yes")

        #
        # Stupid hack for stupid dnsmasq not picking up its new init.d script then breaking everything ...
        # https://forum.yunohost.org/t/20676
        #
        # FIXME : this is from buster->bullseye, do we still needed it ?
        #
        #if os.path.exists("/etc/init.d/dnsmasq.dpkg-dist"):
        #    logger.info("Copying new version for /etc/init.d/dnsmasq ...")
        #    os.system("cp /etc/init.d/dnsmasq.dpkg-dist /etc/init.d/dnsmasq")

        #
        # Yunohost upgrade
        #
        logger.info(m18n.n("migration_0027_yunohost_upgrade"))

        aptitude_with_progress_bar(f"unhold yunohost moulinette ssowat yunohost-admin {' '.join(apps_packages)}")

        # FIXME : find a way to simulate and validate the upgrade first
        # FIXME : why were libluajit needed in the first place ?
        aptitude_with_progress_bar("full-upgrade --show-why yunohost yunohost-admin moulinette ssowat libluajit-5.1-2- libluajit-5.1-common- -y -o Dpkg::Options::='--force-confold'")

        #cmd = "LC_ALL=C"
        #cmd += " DEBIAN_FRONTEND=noninteractive"
        #cmd += " APT_LISTCHANGES_FRONTEND=none"
        #cmd += " apt dist-upgrade "
        #cmd += " --quiet -o=Dpkg::Use-Pty=0 --fix-broken --dry-run"
        #cmd += " | grep -q 'ynh-deps'"

        #logger.info("Simulating upgrade...")
        #if os.system(cmd) == 0:
        #    raise YunohostError(
        #        "The upgrade cannot be completed, because some app dependencies would need to be removed?",
        #        raw_msg=True,
        #    )

        # FIXME :
        #postupgradecmds = "rm -f /usr/sbin/policy-rc.d\n"
        #postupgradecmds += "echo 'Restarting nginx...' >&2\n"
        #postupgradecmds += "systemctl restart nginx\n"

    def debian_major_version(self):
        # The python module "platform" and lsb_release are not reliable because
        # on some setup, they may still return Release=9 even after upgrading to
        # buster ... (Apparently this is related to OVH overriding some stuff
        # with /etc/lsb-release for instance -_-)
        # Instead, we rely on /etc/os-release which should be the raw info from
        # the distribution...
        return int(
            check_output(
                "grep VERSION_ID /etc/os-release | head -n 1 | tr '\"' ' ' | cut -d ' ' -f2"
            )
        )

    def yunohost_major_version(self):
        return int(get_ynh_package_version("yunohost")["version"].split(".")[0])

    def check_assertions(self):
        # Be on bullseye (11.x) and yunohost 11.x
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be > 12.x but yunohost package
        # would still be in 11.x...
        if (
            not self.debian_major_version() == N_CURRENT_DEBIAN
            and not self.yunohost_major_version() == N_CURRENT_YUNOHOST
        ):
            try:
                # Here we try to find the previous migration log, which should be somewhat recent and be at least 10k (we keep the biggest one)
                maybe_previous_migration_log_id = check_output(
                    "cd /var/log/yunohost/categories/operation && find -name '*migrate*.log' -size +10k -mtime -100 -exec ls -s {} \\; | sort -n | tr './' ' ' | awk '{print $2}' | tail -n 1"
                )
                if maybe_previous_migration_log_id:
                    logger.info(
                        f"NB: the previous migration log id seems to be {maybe_previous_migration_log_id}. You can share it with the support team with : sudo yunohost log share {maybe_previous_migration_log_id}"
                    )
            except Exception:
                # Yeah it's not that important ... it's to simplify support ...
                pass

            raise YunohostError("migration_0027_not_bullseye")

        # Have > 1 Go free space on /var/ ?
        if free_space_in_directory("/var/") / (1024**3) < 1.0:
            raise YunohostError("migration_0027_not_enough_free_space")

        # Have > 70 MB free space on /var/ ?
        if free_space_in_directory("/boot/") / (1024**2) < 70.0:
            raise YunohostError(
                "/boot/ has less than 70MB available. This will probably trigger a crash during the upgrade because a new kernel needs to be installed. Please look for advice on the forum on how to remove old, unused kernels to free up some space in /boot/.",
                raw_msg=True,
            )

        # Check system is up to date
        # (but we don't if 'bullseye' is already in the sources.list ...
        # which means maybe a previous upgrade crashed and we're re-running it)
        if os.path.exists("/etc/apt/sources.list") and " bookworm " not in read_file(
            "/etc/apt/sources.list"
        ):
            tools_update(target="system")
            upgradable_system_packages = list(_list_upgradable_apt_packages())
            upgradable_system_packages = [
                package["name"] for package in upgradable_system_packages
            ]
            upgradable_system_packages = set(upgradable_system_packages)
            # Lime2 have hold packages to avoid ethernet instability
            # See https://github.com/YunoHost/arm-images/commit/b4ef8c99554fd1a122a306db7abacc4e2f2942df
            lime2_hold_packages = set(
                [
                    "armbian-firmware",
                    "armbian-bsp-cli-lime2",
                    "linux-dtb-current-sunxi",
                    "linux-image-current-sunxi",
                    "linux-u-boot-lime2-current",
                    "linux-image-next-sunxi",
                ]
            )
            if upgradable_system_packages - lime2_hold_packages:
                raise YunohostError("migration_0027_system_not_fully_up_to_date")

    @property
    def disclaimer(self):
        # Avoid having a super long disclaimer + uncessary check if we ain't
        # on bullseye / yunohost 11.x
        # NB : we do both check to cover situations where the upgrade crashed
        # in the middle and debian version could be 12.x but yunohost package
        # would still be in 11.x...
        if (
            not self.debian_major_version() == N_CURRENT_DEBIAN
            and not self.yunohost_major_version() == N_CURRENT_YUNOHOST
        ):
            return None

        # Get list of problematic apps ? I.e. not official or community+working
        problematic_apps = unstable_apps()
        problematic_apps = "".join(["\n    - " + app for app in problematic_apps])

        # Manually modified files ? (c.f. yunohost service regen-conf)
        modified_files = manually_modified_files()
        modified_files = "".join(["\n    - " + f for f in modified_files])

        message = m18n.n("migration_0027_general_warning")

        message = (
            "N.B.: This migration has been tested by the community over the last few months but has only been declared stable recently. If your server hosts critical services and if you are not too confident with debugging possible issues, we recommend you to wait a little bit more while we gather more feedback and polish things up. If on the other hand you are relatively confident with debugging small issues that may arise, you are encouraged to run this migration ;)! You can read about remaining known issues and feedback from the community here: https://forum.yunohost.org/t/?? FIXME ?? \n\n"
            + message
            + "\n\n"
            + "Packages 'metronome' (xmpp server) and 'rspamd' (mail antispam) are now optional dependencies and may get uninstalled during the upgrade. Make sure to explicitly re-install those using 'apt install' after the upgrade if you care about those!"
        )

        if problematic_apps:
            message += "\n\n" + m18n.n(
                "migration_0027_problematic_apps_warning",
                problematic_apps=problematic_apps,
            )

        if modified_files:
            message += "\n\n" + m18n.n(
                "migration_0027_modified_files", manually_modified_files=modified_files
            )

        return message

    def patch_apt_sources_list(self):
        sources_list = glob.glob("/etc/apt/sources.list.d/*.list")
        if os.path.exists("/etc/apt/sources.list"):
            sources_list.append("/etc/apt/sources.list")

        # This :
        # - replace single 'bullseye' occurence by 'bookworm'
        # - comments lines containing "backports"
        # - replace 'bullseye/updates' by 'bookworm/updates' (or same with -)
        # - make sure the yunohost line has the "signed-by" thingy
        # Special note about the security suite:
        # https://www.debian.org/releases/bullseye/amd64/release-notes/ch-information.en.html#security-archive
        for f in sources_list:
            command = (
                f"sed -i {f} "
                "-e 's@ bullseye @ bookworm @g' "
                "-e '/backports/ s@^#*@#@' "
                "-e 's@ bullseye/updates @ bookworm-security @g' "
                "-e 's@ bullseye-@ bookworm-@g' "
                "-e 's@deb.*http://forge.yunohost.org@deb [signed-by=/usr/share/keyrings/yunohost-bookworm.gpg] http://forge.yunohost.org@g' "
            )
            os.system(command)

        # Stupid OVH has some repo configured which dont work with next debian and break apt ...
        os.system("rm -f /etc/apt/sources.list.d/ovh-*.list")

    def get_apps_equivs_packages(self):
        command = (
            "dpkg --get-selections"
            " | grep -v deinstall"
            " | awk '{print $1}'"
            " | { grep 'ynh-deps$' || true; }"
        )

        output = check_output(command)

        return output.split("\n") if output else []

    def get_php_packages(self):
        command = (
            "dpkg --get-selections"
            " | grep -v deinstall"
            " | awk '{print $1}'"
            " | { grep '^php' || true; }"
        )

        output = check_output(command)

        return output.split("\n") if output else []

    def patch_yunohost_conflicts(self):
        #
        # This is a super dirty hack to remove the conflicts from yunohost's debian/control file
        # Those conflicts are there to prevent mistakenly upgrading critical packages
        # such as dovecot, postfix, nginx, openssl, etc... usually related to mistakenly
        # using backports etc.
        #
        # The hack consists in savagely removing the conflicts directly in /var/lib/dpkg/status
        #

        # We only patch the conflict if we're on yunohost 11.x
        if self.yunohost_major_version() != N_CURRENT_YUNOHOST:
            return

        conflicts = check_output("dpkg-query -s yunohost | grep '^Conflicts:'").strip()
        if conflicts:
            # We want to keep conflicting with apache/bind9 tho
            new_conflicts = "Conflicts: apache2, bind9"

            command = (
                f"sed -i /var/lib/dpkg/status -e 's@{conflicts}@{new_conflicts}@g'"
            )
            logger.debug(f"Running: {command}")
            os.system(command)

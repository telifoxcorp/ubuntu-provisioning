#!/bin/bash
# Name: Ubuntu 26.04 | Validate Initial Provisioning
# Description: Read-only verification of the companion autoinstall pilot.
# Not a full CIS audit or an Intune custom compliance discovery script.
# Usage: sudo bash verify_ubuntu_baseline.sh [--json]
# Exit: 0=checks pass, 1=failed checks, 2=pending reboot/provisioning or review.
# Produces stdout only; optional report saving is controlled by the operator.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
if [ "$(id -u)" -ne 0 ]; then echo 'Run with sudo for complete results.' >&2; exit 1; fi
command -v python3 >/dev/null || { echo 'Python 3 is required.' >&2; exit 1; }
exec python3 - "$@" <<'PY'
import subprocess, pathlib, json, sys, re, datetime, shlex
if any(a!='--json' for a in sys.argv[1:]):
    print('Usage: sudo bash verify_ubuntu_baseline.sh [--json]',file=sys.stderr);sys.exit(1)
results=[]
def run(*args):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=45)
        return p.returncode,p.stdout.strip(),p.stderr.strip()
    except (OSError,subprocess.TimeoutExpired) as e:return 127,'',str(e)
def add(name,status,detail):results.append(dict(check=name,status=status,detail=detail))
def check(name,ok,detail):add(name,'PASS' if ok else 'FAIL',detail)
state=pathlib.Path('/var/lib/company-provisioning')
marker=(state/'completed-v1').is_file()
rc,active,_=run('systemctl','is-active','company-provision.service')
add('Provisioning completion','PASS' if marker else 'PENDING' if active in ('active','activating') else 'FAIL',
    f'marker={marker}; service={active}; marker is not used as proof of individual checks')
osinfo={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        k,v=line.split('=',1);osinfo[k]=v.strip('"')
check('Operating system',osinfo.get('ID')=='ubuntu' and osinfo.get('VERSION_ID')=='26.04',str(osinfo.get('PRETTY_NAME')))
rc,arch,_=run('dpkg','--print-architecture');check('Architecture',rc==0 and arch=='amd64',arch)
rc,cloud,_=run('cloud-init','status')
add('Cloud-init','PASS' if rc==0 and 'done' in cloud else 'PENDING' if 'running' in cloud else 'FAIL',cloud or 'cloud-init status unavailable')
rc,root,_=run('findmnt','-n','-o','SOURCE','/')
rc2,types,err=run('lsblk','-s','-n','-o','TYPE',root)
check('Encrypted root ancestry',rc==rc2==0 and 'crypt' in types.split(),f'{root}: {types.replace(chr(10),", ")} {err}')
for pkg in ['google-chrome-stable','microsoft-edge-stable','1password','zoom','intune-portal','apparmor','auditd','ufw','unattended-upgrades']:
    rc,value,_=run('dpkg-query','-W','-f=${Status} | ${Version}',pkg)
    check('Package: '+pkg,rc==0 and value.startswith('install ok installed |'),value or 'not installed')
apps={'outlook':'https://outlook.office.com/','microsoft365':'https://www.microsoft365.com/',
      'teams':'https://teams.microsoft.com/','chatgpt':'https://chatgpt.com/','copilot':'https://copilot.microsoft.com/'}
for name,url in apps.items():
    p=pathlib.Path('/usr/share/applications/company-'+name+'.desktop')
    text=p.read_text() if p.exists() else ''
    check('Web launcher: '+name,'Exec=/usr/bin/microsoft-edge --app='+url in text,str(p))
for unit in ['apparmor','auditd','systemd-journald']:
    rc,value,_=run('systemctl','is-active',unit)
    check('Service: '+unit,rc==0 and value=='active',value)
rc,profiles,_=run('aa-status','--json')
if rc==0:
    try:
        modes=json.loads(profiles).get('profiles',{})
        check('AppArmor enforced profiles',isinstance(modes,dict) and 'enforce' in modes.values(),f'{len(modes)} profiles; at least one must be enforced')
    except (ValueError,TypeError):add('AppArmor enforced profiles','FAIL','Cannot parse aa-status JSON')
else:add('AppArmor enforced profiles','FAIL','aa-status --json did not succeed')
rc,fw,_=run('ufw','status','verbose')
check('Firewall enabled',rc==0 and 'Status: active' in fw,fw)
check('Firewall incoming policy','deny (incoming)' in fw,'Expected deny incoming; rule exceptions still require review')
for unit in ['apt-daily.timer','apt-daily-upgrade.timer']:
    a,enabled,_=run('systemctl','is-enabled',unit);b,running,_=run('systemctl','is-active',unit)
    check('Update timer: '+unit,a==b==0 and running=='active',f'{enabled}; {running}')
rc,apt,_=run('apt-config','dump')
for key in ['APT::Periodic::Update-Package-Lists','APT::Periodic::Unattended-Upgrade']:
    check('Update setting: '+key,rc==0 and re.search(re.escape(key)+r'\s+"1";',apt)!=None,'Expected effective value 1')
check('No automatic update reboot',rc==0 and re.search(r'Unattended-Upgrade::Automatic-Reboot\s+"false";',apt)!=None,'Expected effective value false')
fstab=[]
for line in pathlib.Path('/etc/fstab').read_text().splitlines():
    if line.strip() and not line.lstrip().startswith('#'):fstab.append(line.split())
for target in ['/tmp','/dev/shm']:
    entries=[f for f in fstab if len(f)>=4 and f[1]==target]
    persistent=len(entries)==1 and {'nodev','nosuid','noexec'}.issubset(set(entries[0][3].split(',')))
    check('Persistent mount: '+target,persistent,str(entries))
    rc,raw,_=run('findmnt','-J','-M',target,'-o','TARGET,FSTYPE,OPTIONS')
    live=False
    try:
        fs=json.loads(raw)['filesystems'][0]
        live=rc==0 and fs['target']==target and fs['fstype'] not in ('overlay','autofs') and {'nodev','nosuid','noexec'}.issubset(set(fs['options'].split(',')))
    except (ValueError,KeyError,IndexError,TypeError):pass
    add('Live mount: '+target,'PASS' if live else 'PENDING' if persistent else 'FAIL',raw or 'No exact mount; reboot if configuration was just staged')
    p=pathlib.Path(target); st=p.stat()
    check('Permissions: '+target,st.st_uid==st.st_gid==0 and (st.st_mode & 0o7777)==0o1777,f'uid={st.st_uid} gid={st.st_gid} mode={oct(st.st_mode & 0o7777)}')
rc,config,_=run('modprobe','--showconfig')
loaded={line.split()[0] for line in pathlib.Path('/proc/modules').read_text().splitlines()}
for module in ['cramfs','freevxfs','jffs2']:
    blocked=rc==0 and re.search(r'^install\s+'+module+r'\s+/bin/false\s*$',config,re.M)!=None and re.search(r'^blacklist\s+'+module+r'\s*$',config,re.M)!=None
    # Reject competing install rules rather than silently ignoring them.
    rules=[line.split() for line in config.splitlines() if line.startswith('install ') and len(line.split())>1 and line.split()[1]==module]
    check('Module: '+module,blocked and module not in loaded and all(r==['install',module,'/bin/false'] for r in rules),f'blocked={blocked}; loaded={module in loaded}')
reboot=pathlib.Path('/var/run/reboot-required').exists()
if reboot:add('System restart','PENDING','/var/run/reboot-required exists')
add('Manual acceptance','REVIEW','Confirm Intune enrollment/compliance, standard-user access, app sign-in, Zoom media, and full CIS audit. Not verified by this script.')
counts={s:sum(r['status']==s for r in results) for s in ['PASS','FAIL','PENDING','REVIEW']}
code=1 if counts['FAIL'] else 2 if counts['PENDING'] else 0
output=dict(timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),scope='Autoinstall pilot validation, not full CIS compliance',exit_code=code,counts=counts,checks=results)
if '--json' in sys.argv:print(json.dumps(output,indent=2))
else:
    for r in results:print(f"[{r['status']}] {r['check']}: {r['detail']}")
    print('\nSummary: '+str(counts));print('Exit code: '+str(code))
sys.exit(code)
PY

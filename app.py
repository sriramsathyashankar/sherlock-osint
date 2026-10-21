#!/usr/bin/env python3
"""Sherlock - AI-powered Digital Forensics Assistant"""

import os
import re
import io
import sys
import shlex
import json
import shutil
import hashlib
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sherlock-dev-key')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True

# OSINT Repositories configuration
OSINT_REPOS = {
    'sherlock': {
        'name': 'Sherlock',
        'description': 'Search usernames across 400+ social networks',
        'type': 'username',
        'stars': 94500,
        'url': 'https://github.com/sherlock-project/sherlock',
        'install': 'pip install git+https://github.com/sherlock-project/sherlock.git',
        'command': 'python3 sherlock.py',
        'parameters': '<username>'
    },
    'maigret': {
        'name': 'Maigret',
        'description': 'Build username-based dossier from 5,900 sites',
        'type': 'username',
        'stars': 39200,
        'url': 'https://github.com/soxoj/maigret',
        'install': 'pip install maigret',
        'command': 'python3 -m maigret',
        'parameters': '<username>'
    },
    'social-analyzer': {
        'name': 'Social Analyzer',
        'description': 'API/CLI/web app for 1,000+ social-media sites',
        'type': 'username',
        'stars': 24300,
        'url': 'https://github.com/qeeqbox/social-analyzer',
        'install': 'pip install social-analyzer',
        'command': 'social-analyzer',
        'parameters': '<username>'
    },
    'blackbird': {
        'name': 'Blackbird',
        'description': 'Search 600+ platforms by username or email',
        'type': 'username/email',
        'stars': 9200,
        'url': 'https://github.com/antoniaci/blackbird',
        'install': 'pip install blackbird',
        'command': 'python3 -m blackbird',
        'parameters': '<username or email>'
    },
    'ghunt': {
        'name': 'GHunt',
        'description': 'Google-focused OSINT framework',
        'type': 'email',
        'stars': 19700,
        'url': 'https://github.com/mxrch/GHunt',
        'install': 'pip install ghunt',
        'command': 'python3 -m ghunt',
        'parameters': '<email>'
    },
    'holehe': {
        'name': 'Holehe',
        'description': 'Check email across 120+ services',
        'type': 'email',
        'stars': 15200,
        'url': 'https://github.com/megadose/holehe',
        'install': 'pip install holehe',
        'command': 'python3 -m holehe',
        'parameters': '<email>'
    },
    'h8mail': {
        'name': 'h8mail',
        'description': 'Email OSINT and password-breach-hunting',
        'type': 'email',
        'stars': 5400,
        'url': 'https://github.com/khast3x/h8mail',
        'install': 'pip install h8mail',
        'command': 'h8mail',
        'parameters': '<email>'
    },
    'theHarvester': {
        'name': 'theHarvester',
        'description': 'Collect organization/domain public information',
        'type': 'domain',
        'stars': 18000,
        'url': 'https://github.com/laramies/theHarvester',
        'install': 'pip install theHarvester',
        'command': 'theHarvester',
        'parameters': '-d <domain> -b all'
    },
    'amass': {
        'name': 'Amass',
        'description': 'Network mapping and external asset discovery',
        'type': 'domain',
        'stars': 15400,
        'url': 'https://github.com/owasp-amass/amass',
        'install': 'go install -v github.com/owasp-amass/amass/v3@latest',
        'command': 'amass',
        'parameters': 'enum -d <domain>'
    },
    'subfinder': {
        'name': 'Subfinder',
        'description': 'Fast passive subdomain enumeration',
        'type': 'domain',
        'stars': 14600,
        'url': 'https://github.com/projectdiscovery/subfinder',
        'install': 'go install -v github.com/projectdiscovery/subfinder/cmd/subfinder@latest',
        'command': 'subfinder',
        'parameters': '-d <domain>'
    },
    'photon': {
        'name': 'Photon',
        'description': 'Fast crawler for OSINT and website footprint',
        'type': 'domain',
        'stars': 13300,
        'url': 'https://github.com/s0md3v/Photon',
        'install': 'pip install photon',
        'command': 'python3 -c "from photon import photon; photon()"'
    },
    'dnstwist': {
        'name': 'dnstwist',
        'description': 'Domain permutations for typosquatting detection',
        'type': 'domain',
        'stars': 5800,
        'url': 'https://github.com/elceef/dnstwist',
        'install': 'pip install dnstwist',
        'command': 'dnstwist',
        'parameters': '<domain>'
    },
    'phoneinfoga': {
        'name': 'PhoneInfoga',
        'description': 'Gather phone number details and metadata',
        'type': 'phone',
        'stars': 18200,
        'url': 'https://github.com/sundowndev/phoneinfoga',
        'install': 'pip install phoneinfoga',
        'command': 'python3 -m phoneinfoga',
        'parameters': '<phone_number>'
    },
    'trufflehog': {
        'name': 'TruffleHog',
        'description': 'Find exposed credentials and secrets',
        'type': 'general',
        'stars': 28600,
        'url': 'https://github.com/trufflesecurity/trufflehog',
        'install': 'pip install trufflehog',
        'command': 'trufflehog',
        'parameters': '<target>'
    },
    'spiderfoot': {
        'name': 'SpiderFoot',
        'description': 'Broad OSINT automation with 200+ modules',
        'type': 'general',
        'stars': 23600,
        'url': 'https://github.com/smicallef/spiderfoot',
        'install': 'pip install spiderfoot',
        'command': 'python3 -m sf',
        'parameters': '-t <target>'
    },
    'exiftool': {
        'name': 'ExifTool',
        'description': 'Metadata reader/writer for digital forensics',
        'type': 'metadata',
        'stars': 5200,
        'url': 'https://github.com/exiftool/exiftool',
        'install': 'pip install exiftool',
        'command': 'exiftool',
        'parameters': '<file>'
    }
}

# Pipeline configuration
PIPELINE_CONFIG = {
    'username': {
        'stages': [
            {'id': 'stage-1', 'name': 'Username Pattern Analysis', 'type': 'analysis', 'prerequisites': []},
            {'id': 'stage-2', 'name': 'Social Media Platform Search', 'type': 'search', 'prerequisites': ['stage-1'], 'repo': 'sherlock'},
            {'id': 'stage-3', 'name': 'Cross-Platform Correlation', 'type': 'correlation', 'prerequisites': ['stage-2'], 'repos': ['maigret', 'social-analyzer', 'blackbird']},
            {'id': 'stage-4', 'name': 'Profile Detail Enrichment', 'type': 'enrichment', 'prerequisites': ['stage-3'], 'repos': ['ghunt', 'h8mail']},
            {'id': 'stage-5', 'name': 'Digital Footprint Mapping', 'type': 'mapping', 'prerequisites': ['stage-4'], 'repos': ['theHarvester', 'amass', 'subfinder']},
            {'id': 'stage-6', 'name': 'Final Synthesis & Report', 'type': 'synthesis', 'prerequisites': ['stage-5']}
        ]
    },
    'email': {
        'stages': [
            {'id': 'stage-1', 'name': 'Email Format Analysis', 'type': 'analysis', 'prerequisites': []},
            {'id': 'stage-2', 'name': 'Service Registration Check', 'type': 'search', 'prerequisites': ['stage-1'], 'repo': 'holehe'},
            {'id': 'stage-3', 'name': 'Breach Database Lookup', 'type': 'breach', 'prerequisites': ['stage-2'], 'repo': 'h8mail'},
            {'id': 'stage-4', 'name': 'Google Account Analysis', 'type': 'google', 'prerequisites': ['stage-3'], 'repo': 'ghunt'},
            {'id': 'stage-5', 'name': 'Identity Correlation', 'type': 'correlation', 'prerequisites': ['stage-4'], 'repos': ['spiderfoot']},
            {'id': 'stage-6', 'name': 'Final Synthesis & Report', 'type': 'synthesis', 'prerequisites': ['stage-5']}
        ]
    },
    'name': {
        'stages': [
            {'id': 'stage-1', 'name': 'Name Decomposition', 'type': 'analysis', 'prerequisites': []},
            {'id': 'stage-2', 'name': 'Social Media Search', 'type': 'search', 'prerequisites': ['stage-1'], 'repo': 'maigret'},
            {'id': 'stage-3', 'name': 'Public Record Lookup', 'type': 'records', 'prerequisites': ['stage-2'], 'repos': ['theHarvester']},
            {'id': 'stage-4', 'name': 'Professional Profile Analysis', 'type': 'enrichment', 'prerequisites': ['stage-3'], 'repos': ['photon']},
            {'id': 'stage-5', 'name': 'Footprint Synthesis', 'type': 'synthesis', 'prerequisites': ['stage-4'], 'repos': ['spiderfoot']},
            {'id': 'stage-6', 'name': 'Final Synthesis & Report', 'type': 'final', 'prerequisites': ['stage-5']}
        ]
    },
    'comprehensive': {
        'stages': [
            {'id': 'stage-1', 'name': 'Initial Reconnaissance', 'type': 'analysis', 'prerequisites': []},
            {'id': 'stage-2', 'name': 'Username Tracking', 'type': 'search', 'prerequisites': ['stage-1'], 'repo': 'sherlock'},
            {'id': 'stage-3', 'name': 'Email Service Check', 'type': 'search', 'prerequisites': ['stage-2'], 'repo': 'holehe'},
            {'id': 'stage-4', 'name': 'Name-Based Search', 'type': 'search', 'prerequisites': ['stage-3'], 'repo': 'maigret'},
            {'id': 'stage-5', 'name': 'Cross-Referencing', 'type': 'correlation', 'prerequisites': ['stage-4'], 'repos': ['blackbird', 'social-analyzer']},
            {'id': 'stage-6', 'name': 'Pattern Analysis', 'type': 'analysis', 'prerequisites': ['stage-5'], 'repos': ['dnstwist', 'photon']},
            {'id': 'stage-7', 'name': 'Final Synthesis & Detailed Report', 'type': 'synthesis', 'prerequisites': ['stage-6']}
        ]
    }
}


def _fetch_json(url, timeout=6):
    """Small, dependency-free JSON GET with a Sherlock user agent."""
    req = urllib.request.Request(url, headers={'User-Agent': 'Sherlock-OSINT/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8', 'replace'))


def builtin_lookup(target, kind='auto'):
    """Passive lookups that need no external binaries or API keys.

    Returns a list of finding dicts so a stalled or missing third-party tool
    never leaves a pipeline stage without evidence.
    """
    findings = []
    t = (target or '').strip()
    if not t:
        return findings

    looks_email = '@' in t
    looks_domain = '.' in t and not looks_email and ' ' not in t
    handle = t[1:] if t.startswith('@') else t

    if kind in ('auto', 'username') and not looks_email and not looks_domain:
        try:
            gh = _fetch_json(f'https://api.github.com/users/{urllib.parse.quote(handle)}')
            findings.append({
                'source': 'GitHub API',
                'found': True,
                'summary': f"GitHub account '{gh.get('login')}' - {gh.get('public_repos', 0)} public repos",
                'data': {
                    'name': gh.get('name'),
                    'company': gh.get('company'),
                    'location': gh.get('location'),
                    'blog': gh.get('blog'),
                    'created_at': gh.get('created_at'),
                    'public_repos': gh.get('public_repos'),
                    'followers': gh.get('followers'),
                    'url': gh.get('html_url'),
                }
            })
        except Exception as exc:
            findings.append({'source': 'GitHub API', 'found': False,
                             'summary': f'No GitHub account resolved ({type(exc).__name__})'})

        try:
            gh_events = _fetch_json(
                f'https://api.github.com/users/{urllib.parse.quote(handle)}/repos?per_page=5&sort=updated')
            names = [r.get('name') for r in gh_events if isinstance(r, dict)]
            if names:
                findings.append({'source': 'GitHub repos', 'found': True,
                                 'summary': 'Recently updated repos: ' + ', '.join(names[:5]),
                                 'data': names})
        except Exception:
            pass

    if kind in ('auto', 'email') and looks_email:
        digest = hashlib.md5(t.lower().encode('utf-8')).hexdigest()
        gravatar = f'https://www.gravatar.com/avatar/{digest}?d=404'
        try:
            req = urllib.request.Request(gravatar, method='HEAD',
                                         headers={'User-Agent': 'Sherlock-OSINT/1.0'})
            with urllib.request.urlopen(req, timeout=6) as resp:
                exists = resp.status == 200
        except Exception:
            exists = False
        findings.append({
            'source': 'Gravatar',
            'found': bool(exists),
            'summary': ('Gravatar profile exists for this address' if exists
                        else 'No Gravatar profile associated'),
            'data': {'hash': digest}
        })

        domain = t.split('@', 1)[1]
        try:
            mx = sorted({info[1] for info in socket.getaddrinfo(domain, None)})
            findings.append({'source': 'DNS', 'found': bool(mx),
                             'summary': f'Mail domain {domain} resolves', 'data': mx[:5]})
        except Exception:
            findings.append({'source': 'DNS', 'found': False,
                             'summary': f'Mail domain {domain} did not resolve'})

    if (kind in ('auto', 'domain') and looks_domain) or (looks_email and kind in ('auto', 'mapping')):
        dom = t.split('@', 1)[1] if looks_email else t
        try:
            ip = socket.gethostbyname(dom)
            findings.append({'source': 'DNS', 'found': True,
                             'summary': f'{dom} resolves to {ip}', 'data': {'ip': ip}})
        except Exception:
            findings.append({'source': 'DNS', 'found': False,
                             'summary': f'{dom} did not resolve'})
        try:
            crt = _fetch_json(f'https://crt.sh/?q=%25.{urllib.parse.quote(dom)}&output=json', timeout=10)
            names = sorted({row.get('name_value', '') for row in crt if isinstance(row, dict)})
            subdomains = [n for n in names if n][:25]
            findings.append({'source': 'crt.sh', 'found': bool(subdomains),
                             'summary': f'{len(subdomains)} certificate-transparency subdomain(s)',
                             'data': subdomains})
        except Exception:
            pass

    return findings


def topological_sort(stages):
    """Order stages so every prerequisite runs before its dependents."""
    by_id = {s['id']: s for s in stages}
    result = []
    permanent = set()
    temporary = set()

    def visit(stage_id):
        if stage_id in permanent:
            return
        if stage_id in temporary:
            raise ValueError(f'Cyclic pipeline dependency at {stage_id}')
        stage = by_id.get(stage_id)
        if stage is None:
            return
        temporary.add(stage_id)
        for prereq in stage.get('prerequisites', []):
            visit(prereq)
        temporary.discard(stage_id)
        permanent.add(stage_id)
        result.append(stage_id)

    for stage in stages:
        visit(stage['id'])

    return result


def _resolve_builtin_command(command):
    """Turn a built-in tool's command into something that actually runs.

    Console scripts installed in the virtualenv win over "python3 -m pkg",
    because many packages (holehe, ghunt, ...) ship no ``__main__`` module and
    can only be started through the script their installer creates.
    """
    parts = shlex.split(command or '')
    if not parts:
        return command

    # "python3 -m package" -> prefer the console script of the same name.
    if re.match(r'^python3?$', parts[0]) and len(parts) > 2 and parts[1] == '-m':
        module = parts[2]
        script = os.path.join(_venv_bin(), module)
        if os.path.exists(script):
            return shlex.quote(script)
        # Otherwise run the module with the interpreter that has the tools.
        return ' '.join([shlex.quote(sys.executable)]
                        + [shlex.quote(p) for p in parts[1:]])

    # A bare command name -> use the copy inside the virtualenv if it exists.
    head = parts[0]
    if '/' not in head:
        script = os.path.join(_venv_bin(), head)
        if os.path.exists(script):
            parts[0] = shlex.quote(script)
            return ' '.join(parts)

    return command


def run_osint_tool(repo_key, parameter):
    """Run an OSINT tool and return results.

    ``repo_key`` may name a built-in integration or a repository the user
    downloaded from GitHub, in which case it is executed from its own
    checkout inside ``repos/``.
    """
    user_repo = _github_state['repos'].get(repo_key)
    if user_repo:
        return _run_user_tool(user_repo, parameter)

    repo = OSINT_REPOS.get(repo_key)
    if not repo:
        return {'error': f'Unknown repository: {repo_key}', 'repo_key': repo_key}

    command = repo.get('command')
    if not command:
        return {'error': f"No runnable command is configured for {repo.get('name', repo_key)}.",
                'repo': repo.get('name', repo_key), 'repo_key': repo_key}

    # Built-in tools are installed into the virtualenv that runs Sherlock, so
    # "python3 -m x" and console scripts have to resolve there - not in the
    # system Python, which rarely has them.
    env = dict(os.environ)
    env['PATH'] = _venv_bin() + os.pathsep + env.get('PATH', '')
    command = _resolve_builtin_command(command)

    try:
        cmd = f"{command} {parameter}"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

        return {
            'success': result.returncode == 0,
            'output': result.stdout[-2000:] if result.stdout else '',
            'error': result.stderr[-1000:] if result.stderr else '',
            'repo': repo['name'],
            'repo_key': repo_key,
            'timestamp': datetime.utcnow().isoformat()
        }
    except subprocess.TimeoutExpired:
        return {'error': f'Tool timed out after 120 seconds', 'repo': repo['name'],
                'repo_key': repo_key}
    except Exception as e:
        return {'error': str(e), 'repo': repo.get('name', repo_key),
                'repo_key': repo_key}


def _run_user_tool(user_repo, parameter):
    """Execute a downloaded repository as an OSINT tool."""
    entry = (user_repo.get('entry') or '').strip()
    cwd = user_repo.get('path') or ''
    label = user_repo.get('full_name') or user_repo.get('key')

    if not entry:
        return {'success': False, 'output': '', 'error': 'This repository has no runnable entry point.',
                'repo': label, 'repo_key': user_repo.get('key')}

    env = dict(os.environ)
    python_paths = [cwd, os.path.join(cwd, 'src')]
    if env.get('PYTHONPATH'):
        python_paths.append(env['PYTHONPATH'])
    env['PYTHONPATH'] = os.pathsep.join(p for p in python_paths if p)
    # Console scripts land in the interpreter's bin directory, which is not on
    # PATH when Sherlock runs from a virtualenv.
    bin_dir = _venv_bin()
    env['PATH'] = bin_dir + os.pathsep + env.get('PATH', '')

    args = (user_repo.get('args') or '{target}').replace('{target}', shlex.quote(parameter))
    cmd = f"{entry} {args}".strip()
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=cwd if os.path.isdir(cwd) else None,
            env=env,
        )
        return {
            'success': result.returncode == 0,
            'output': result.stdout[-2000:] if result.stdout else '',
            'error': result.stderr[-1000:] if result.stderr else '',
            'repo': label,
            'repo_key': user_repo.get('key'),
            'timestamp': datetime.utcnow().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {'error': 'Tool timed out after 120 seconds', 'repo': label,
                'repo_key': user_repo.get('key')}
    except Exception as exc:
        return {'error': str(exc), 'repo': label, 'repo_key': user_repo.get('key')}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/investigate', methods=['POST'])
def investigate():
    data = request.get_json(silent=True) or {}
    target = (data.get('target') or '').strip()
    investigation_type = (data.get('type') or 'comprehensive').strip()

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    return jsonify(run_pipeline(target, investigation_type))


def run_pipeline(target, investigation_type, narrative=True, progress=None):
    """Run the whole prerequisite-ordered pipeline and build the report.

    Shared by the direct /api/investigate route and the chat agent, so both
    paths produce exactly the same evidence. Pass ``narrative=False`` when the
    caller writes the briefing itself, and ``progress`` to be told what each
    stage is doing while it happens.
    """
    investigation_type = investigation_type or 'comprehensive'
    
    # Build pipeline based on investigation type
    config = PIPELINE_CONFIG.get(investigation_type, PIPELINE_CONFIG['comprehensive'])
    
    # Topological sort to determine execution order
    stage_ids = topological_sort(config['stages'])
    
    results = []
    pipeline_stages = []

    # One passive lookup round, reused wherever a third-party tool has nothing.
    passive_findings = []
    try:
        passive_findings = builtin_lookup(target, 'auto')
    except Exception as exc:
        passive_findings = [{'source': 'builtin', 'found': False, 'summary': str(exc)[:120]}]

    for stage_id in stage_ids:
        stage = next(s for s in config['stages'] if s['id'] == stage_id)
        
        stage_result = {
            'id': stage_id,
            'name': stage['name'],
            'status': 'running',
            'start_time': datetime.utcnow().isoformat(),
            'repo_used': stage.get('repo', 'multiple'),
            'findings': []
        }
        pipeline_stages.append(stage_result)
        
        # Execute prerequisites first (already done by topo sort)
        # Execute the relevant tools for this stage
        
        stage_tools = _resolve_stage_tools(investigation_type, stage)

        if stage['type'] in TOOL_STAGE_TYPES and stage_tools:
            for repo_key in stage_tools:
                tool_result = run_osint_tool(repo_key, target)
                stage_result['findings'].append(tool_result)
                stage_result['findings'].append({
                    'type': 'tool_output',
                    'repo': tool_result.get('repo', repo_key),
                    'repo_key': repo_key,
                    'data': parse_tool_output(tool_result, repo_key)
                })
        
        elif stage['type'] == 'analysis':
            # Generic analysis - no tool run, just marking
            pass
        
        elif stage['type'] == 'final':
            # Synthesize all findings
            all_findings = []
            for s in pipeline_stages:
                all_findings.extend(s.get('findings', []))
            
            stage_result['findings'] = all_findings
            # Generate stitched report
            stage_result['stitched_report'] = synthesize_report(all_findings, investigation_type, target)
        
        # Ensure every stage carries evidence, even with no external binaries installed.
        if not stage_result['findings'] and passive_findings:
            for f in passive_findings:
                stage_result['findings'].append({
                    'type': 'passive',
                    'repo': f.get('source', 'builtin'),
                    'data': f,
                })

        stage_result['status'] = 'completed'
        stage_result['end_time'] = datetime.utcnow().isoformat()
        if progress:
            try:
                progress({'stage': stage['name'], 'index': stage_ids.index(stage_id) + 1,
                          'total': len(stage_ids), 'status': 'completed'})
            except Exception:  # noqa: BLE001 - progress must never break a case
                pass

    # Always produce a stitched report from every finding collected above.
    all_findings = []
    for s in pipeline_stages:
        for f in s.get('findings', []):
            if isinstance(f, dict):
                f.setdefault('repo', s.get('repo_used', ''))
            all_findings.append(f)
    stitched_report = synthesize_report(all_findings, investigation_type, target)
    stitched_report['target'] = target
    stitched_report['pipeline_stages'] = len(pipeline_stages)

    # Let the configured model write the briefing; fall back silently if it fails.
    if narrative:
        try:
            briefing = llm_narrative(stitched_report, target, investigation_type)
        except Exception:
            briefing = None
        if briefing:
            stitched_report['narrative'] = briefing
            stitched_report['narrative_model'] = _llm_config.get('model')

    return {
        'success': True,
        'pipeline_stages': pipeline_stages,
        'results': results,
        'target': target,
        'type': investigation_type,
        'report': stitched_report
    }


def parse_tool_output(result, repo_key):
    """Parse tool output based on repository type"""
    repo = OSINT_REPOS.get(repo_key, {})
    output = result.get('output', '')

    if repo_key in _github_state['repos']:
        # Downloaded repositories have no fixed output format - keep the raw text.
        return {
            'output': output[:2000] if output else '',
            'error': (result.get('error') or '')[:500],
            'success': bool(result.get('success')),
        }
    
    if repo_key == 'sherlock':
        # Parse Sherlock output - usernames found across platforms
        lines = output.split('\n')
        platforms = []
        for line in lines:
            if '[' in line and ']' in line:
                platform = line.split('[')[1].split(']')[0].strip()
                platforms.append(platform)
        return {'platforms_found': platforms, 'total': len(platforms)}
    
    elif repo_key == 'maigret':
        # Parse Maigret output - dossier info
        return {'dossier': output[:500] if output else ''}
    
    elif repo_key == 'holehe':
        # Parse Holehe output
        lines = output.split('\n')
        services = []
        for line in lines:
            if '✓' in line or '✗' in line or 'maybe' in line.lower():
                services.append(line.strip())
        return {'services_checked': len(services), 'details': services}
    
    elif repo_key == 'ghunt':
        # Parse GHunt output - Google info
        return {'google_data': output[:500] if output else ''}
    
    elif repo_key == 'h8mail':
        # Parse h8mail output - breach info
        return {'breach_info': output[:500] if output else ''}
    
    elif repo_key == 'theHarvester':
        # Parse theHarvester output - emails, domains, etc.
        return {'collected': output[:1000] if output else ''}
    
    elif repo_key == 'amass':
        # Parse Amass output - subdomains
        lines = [l for l in output.split('\n') if l.strip() and not l.startswith('#')]
        return {'subdomains': lines}
    
    elif repo_key == 'subfinder':
        # Parse Subfinder output - subdomains
        lines = [l for l in output.split('\n') if l.strip()]
        return {'subdomains': lines}
    
    elif repo_key == 'photon':
        # Parse Photon output - links, resources
        return {'resources': output[:500] if output else ''}
    
    elif repo_key == 'dnstwist':
        # Parse dnstwist output - domain permutations
        lines = [l for l in output.split('\n') if l.strip()]
        return {'permutations': lines}
    
    elif repo_key == 'phoneinfoga':
        # Parse PhoneInfoga output
        return {'phone_info': output[:500] if output else ''}
    
    elif repo_key == 'trufflehog':
        # Parse TruffleHog output - credentials
        return {'credentials_found': output[:500] if output else ''}
    
    elif repo_key == 'spiderfoot':
        # Parse SpiderFoot output
        return {'reports': output[:500] if output else ''}
    
    elif repo_key == 'exiftool':
        # Parse ExifTool output - metadata
        return {'metadata': output[:500] if output else ''}
    
    return {'raw_output': output[:500] if output else ''}


def _extract_platforms(raw):
    """Pull platform names out of "[+] Platform: https://..." style output."""
    platforms = []
    for line in (raw or '').split('\n'):
        if 'http' not in line:
            continue
        name = None
        # "[+] Platform: https://..." / "[*] Platform: https://..."
        match = re.match(r'\s*\[[^\]]{0,3}\]\s*([^:]{1,60}?)\s*:\s*https?://\S+', line)
        if match:
            name = match.group(1).strip()
        else:
            # "[Platform] https://..."
            match = re.match(r'\s*\[([^\]]{1,40})\]\s*https?://\S+', line)
            if match:
                name = match.group(1).strip()
        if not name:
            continue
        if name.lower() in ('found', 'error', 'warning', 'x', '+', '-', '*'):
            continue
        if name not in platforms:
            platforms.append(name)
    return platforms


def _extract_registrations(raw):
    """Parse "[x] site.com" style registration results.

    Returns (registered, checked). ``registered`` holds the sites the address
    was found on, ``checked`` every site the tool looked at.
    """
    registered = []
    checked = []
    for line in (raw or '').split('\n'):
        # The site name must be the last thing on the line, so platform lines
        # like "[+] SoundCloud: https://..." are not mistaken for hits.
        match = re.match(r'\s*\[([xX+!~-])\]\s*(\S+)\s*$', line)
        if not match:
            continue
        marker, name = match.group(1), match.group(2).rstrip(':')
        if not name or ' ' in name:
            continue
        checked.append(name)
        if marker in ('x', 'X', '+'):
            registered.append(name)
    return registered, checked


def synthesize_report(findings, investigation_type, target=''):
    """Synthesize a detailed stitched report from all tool outputs"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    subject = (target or '').strip()
    
    report_sections = {
        'username': {
            'title': 'Sherlock Investigation Report',
            'target_type': 'Username',
            'summary': f'Comprehensive analysis of username "{subject}" across digital platforms' if subject
                       else 'Comprehensive analysis of the username across digital platforms',
            'findings': [],
            'recommendations': []
        },
        'email': {
            'title': 'Email OSINT Investigation Report',
            'target_type': 'Email Address',
            'summary': f'Email address analysis of "{subject}" across services, breaches, and Google accounts' if subject
                       else 'Email address analysis across services, breaches, and Google accounts',
            'findings': [],
            'recommendations': []
        },
        'name': {
            'title': 'Name-Based Investigation Report',
            'target_type': 'Person Name',
            'summary': f'Comprehensive name search and digital footprint analysis for "{subject}"' if subject
                       else 'Comprehensive name search and digital footprint analysis',
            'findings': [],
            'recommendations': []
        },
        'comprehensive': {
            'title': 'Comprehensive Digital Forensics Report',
            'target_type': 'Specified Target',
            'summary': f'Multi-dimensional investigation of "{subject}" covering usernames, emails, domains, and digital footprint' if subject
                       else 'Multi-dimensional investigation covering usernames, emails, domains, and digital footprint',
            'findings': [],
            'recommendations': []
        }
    }
    
    section = report_sections.get(investigation_type, report_sections['comprehensive'])
    
    # Process findings
    all_platforms = []
    all_services = []
    all_subdomains = []
    all_breaches = []
    all_credentials = []
    registered_sites = []
    checked_sites = set()
    
    evidence = []
    seen_evidence = set()

    for finding in findings:
        # Passive/builtin findings carry structured data rather than raw output
        data = finding.get('data')
        tool_output = ''
        tool_error = ''
        tool_success = True

        if isinstance(data, dict) and data.get('summary'):
            key = (data.get('source'), data.get('summary'))
            if key not in seen_evidence:
                seen_evidence.add(key)
                evidence.append({
                    'source': data.get('source') or finding.get('repo') or 'source',
                    'summary': data.get('summary'),
                    'found': bool(data.get('found')),
                })
        elif isinstance(data, dict) and 'output' in data:
            # Output from a tool (built-in or downloaded repository)
            tool_output = (data.get('output') or '').strip()
            tool_error = (data.get('error') or '').strip()
            tool_success = bool(data.get('success', True))
        elif data is None:
            # The raw tool result, which carries the same output.
            tool_output = (finding.get('output') or '').strip()
            tool_error = (finding.get('error') or '').strip()
            tool_success = bool(finding.get('success', True))

        if tool_output or tool_error:
            key = (finding.get('repo_key') or finding.get('repo'), tool_output[:120])
            if key not in seen_evidence:
                seen_evidence.add(key)
                platforms = _extract_platforms(tool_output)
                registered, _checked = _extract_registrations(tool_output)
                if platforms:
                    summary = (f'Found {len(platforms)} platform(s): '
                               + ', '.join(platforms[:10])
                               + ('...' if len(platforms) > 10 else ''))
                elif registered:
                    summary = (f'Registered on {len(registered)} site(s): '
                               + ', '.join(registered[:10])
                               + ('...' if len(registered) > 10 else ''))
                else:
                    lines = [l.strip() for l in tool_output.split('\n') if l.strip()]
                    summary = (' | '.join(lines[:3])[:240] if lines
                               else _friendly_error(tool_error, finding.get('repo')))
                evidence.append({
                    'source': finding.get('repo') or finding.get('repo_key') or 'tool',
                    'summary': summary,
                    'found': bool(tool_success and tool_output),
                })

        raw = finding.get('raw_output', '') or finding.get('output', '')
        if not raw:
            continue
        
        repo_key = finding.get('repo_key') or finding.get('repo', '')
        
        if repo_key == 'sherlock' or repo_key.startswith('user__'):
            # Extract platforms from "[+] Platform: url" style output
            all_platforms.extend(_extract_platforms(raw))
            found, seen = _extract_registrations(raw)
            registered_sites.extend(found)
            checked_sites.update(seen)
        
        elif repo_key == 'holehe':
            all_services.append('Email service registration check completed')
            found, seen = _extract_registrations(raw)
            registered_sites.extend(found)
            checked_sites.update(seen)
        
        elif repo_key == 'h8mail':
            all_breaches.append('Breach database lookup completed')
        
        elif repo_key == 'ghunt':
            all_services.append('Google account analysis completed')
        
        elif repo_key in ['theHarvester', 'amass', 'subfinder']:
            all_subdomains.append(repo_key.upper())
        
        elif repo_key == 'photon':
            all_services.append('Website footprint collection completed')
        
        elif repo_key == 'trufflehog':
            all_credentials.append('Exposed credentials scan completed')
        
        elif repo_key == 'spiderfoot':
            all_services.append('OSINT correlation analysis completed')
    
    confirmed = [e for e in evidence if e['found']]

    # Build summary
    section['findings'] = [
        {
            'category': 'Confirmed Identifiers',
            'detail': (f"{len(confirmed)} source(s) returned confirmed data: "
                       + ', '.join(sorted({e['source'] for e in confirmed})))
                      if confirmed else 'No sources returned confirmed data for this target',
            'status': 'completed' if confirmed else 'not found'
        },
        {
            'category': 'Platform Coverage',
            'detail': (f'Analyzed across {len(set(all_platforms))} unique social media platforms'
                       if all_platforms else
                       'No social media platforms matched this target'),
            'status': 'completed' if all_platforms else 'partial'
        },
        {
            'category': 'Service Registration',
            'detail': (f'{len(registered_sites)} registration(s) found across '
                       f'{len(checked_sites)} service(s) checked'
                       if checked_sites else
                       'No email registration service was checked'),
            'status': ('completed' if registered_sites else
                       'partial' if checked_sites else 'not performed')
        },
        {
            'category': 'Breach Analysis',
            'detail': (f'Checked {len(all_breaches)} breach databases'
                       if all_breaches else
                       'No breach database was queried'),
            'status': 'completed' if all_breaches else 'not performed'
        },
        {
            'category': 'Digital Footprint',
            'detail': (f'Identified {len(all_subdomains)} related domains/subdomains'
                       if all_subdomains else
                       'No domain or subdomain data was collected'),
            'status': 'completed' if all_subdomains else 'not performed'
        },
        {
            'category': 'Credential Exposure',
            'detail': (f'Scanned for {len(all_credentials)} potential exposed credentials'
                       if all_credentials else
                       'No credential source was scanned'),
            'status': 'completed' if all_credentials else 'not performed'
        }
    ]
    
    # Fold collected passive evidence into the report
    for ev in evidence:
        section['findings'].append({
            'category': f"Evidence: {ev['source']}",
            'detail': ev['summary'],
            'status': 'confirmed' if ev['found'] else 'not found'
        })

    # Generate recommendations
    recommendations = []
    if all_platforms:
        recommendations.append('Monitor identified platforms for activity changes')
    if registered_sites:
        recommendations.append('Review account recovery options on the sites where the address is registered')
    if all_breaches:
        recommendations.append('Enable two-factor authentication on all associated accounts')
    if all_subdomains:
        recommendations.append('Check identified subdomains for typosquatting threats')
    if all_credentials:
        recommendations.append('Rotate all exposed credentials immediately')
    recommendations.append('Regular monitoring recommended for ongoing digital footprint assessment')
    
    section['recommendations'] = recommendations
    
    return section


@app.route('/api/pipeline-status', methods=['GET'])
def pipeline_status():
    """Get current pipeline status"""
    # Return static pipeline config since state is client-side only
    config = PIPELINE_CONFIG.get('comprehensive', PIPELINE_CONFIG['comprehensive'])
    stage_ids = topological_sort(config['stages'])
    stages = []
    for stage_id in stage_ids:
        stage = next(s for s in config['stages'] if s['id'] == stage_id)
        stages.append({
            'id': stage['id'],
            'name': stage['name'],
            'type': stage['type']
        })
    return jsonify({'stages': stages})


# ---------------------------------------------------------------------------
# Model providers
# ---------------------------------------------------------------------------

PROVIDERS = {
    'openai': {
        'label': 'OpenAI',
        'base': 'https://api.openai.com/v1',
        'auth': 'bearer',
        'keyless': False,
        'editable_base': False,
    },
    'anthropic': {
        'label': 'Anthropic',
        'base': 'https://api.anthropic.com/v1',
        'auth': 'anthropic',
        'keyless': False,
        'editable_base': False,
    },
    'gemini': {
        'label': 'Google Gemini',
        'base': 'https://generativelanguage.googleapis.com/v1beta',
        'auth': 'query',
        'keyless': False,
        'editable_base': False,
    },
    'openrouter': {
        'label': 'OpenRouter',
        'base': 'https://openrouter.ai/api/v1',
        'auth': 'bearer',
        'keyless': False,
        'editable_base': False,
    },
    'ollama': {
        'label': 'Ollama (local)',
        'base': 'http://127.0.0.1:11434',
        'auth': 'none',
        'keyless': True,
        'key_required': False,
        'editable_base': True,
    },
    'custom': {
        'label': 'OpenAI-compatible endpoint',
        'base': '',
        'auth': 'bearer',
        'keyless': False,
        'key_required': False,  # endpoint URL alone is enough
        'editable_base': True,
    },
}

# Backfill key_required for the hosted providers.
for _meta in PROVIDERS.values():
    _meta.setdefault('key_required', not _meta['keyless'])


def _normalize_base(url):
    """Accept whatever URL the user pastes and reduce it to an API root."""
    if not url:
        return ''
    u = url.strip().rstrip('/')
    for suffix in ('/chat/completions', '/completions', '/models', '/api/tags', '/api'):
        if u.endswith(suffix):
            u = u[: -len(suffix)]
    return u.rstrip('/')


def _looks_like_url(value):
    v = (value or '').strip().lower()
    return v.startswith('http://') or v.startswith('https://')

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models', 'config.json')

_llm_config = {
    'provider': None,
    'model': None,
    'base_url': None,
    'api_key': None,
}


def _load_llm_config():
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
            stored = json.load(fh)
        for key in _llm_config:
            if stored.get(key) is not None:
                _llm_config[key] = stored[key]
    except (OSError, ValueError):
        pass


def _persist_llm_config():
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp = CONFIG_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(_llm_config, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def _public_llm_config():
    return {
        'provider': _llm_config.get('provider'),
        'model': _llm_config.get('model'),
        'base_url': _llm_config.get('base_url'),
        'has_key': bool(_llm_config.get('api_key')),
    }


def _provider_models(provider, base_url, api_key):
    """Ask the provider which models the supplied key can use."""
    meta = PROVIDERS[provider]
    base = _normalize_base(base_url or meta['base'])

    if provider == 'ollama':
        url = f'{base}/api/tags'
    elif provider == 'gemini':
        url = f'{base}/models?key={urllib.parse.quote(api_key)}'
    else:
        url = f'{base}/models'

    headers = {'User-Agent': 'Sherlock-OSINT/1.0', 'Accept': 'application/json'}
    if meta['auth'] == 'bearer' and api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    elif meta['auth'] == 'anthropic':
        headers['x-api-key'] = api_key
        headers['anthropic-version'] = '2023-06-01'

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode('utf-8', 'replace'))
    except urllib.error.HTTPError as exc:
        # Many OpenAI-compatible servers live under /v1; retry there once.
        if (provider == 'custom' and exc.code == 404
                and not base.rstrip('/').endswith('/v1')):
            retry_base = base.rstrip('/') + '/v1'
            retry_url = f'{retry_base}/models'
            retry_req = urllib.request.Request(retry_url, headers=headers)
            with urllib.request.urlopen(retry_req, timeout=15) as resp:
                payload = json.loads(resp.read().decode('utf-8', 'replace'))
            base = retry_base
        else:
            raise

    if provider == 'ollama':
        return sorted({m.get('name') for m in payload.get('models', []) if m.get('name')})
    if provider == 'gemini':
        names = []
        for m in payload.get('models', []):
            name = m.get('name', '')
            if name.startswith('models/'):
                name = name.split('/', 1)[1]
            if name:
                names.append(name)
        return sorted(set(names))

    return sorted({m.get('id') for m in payload.get('data', []) if m.get('id')})


def _explain_provider_error(exc, provider, base_url):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return f'{PROVIDERS[provider]["label"]} rejected the API key (HTTP {exc.code}).'
        if exc.code == 404:
            return f'No models endpoint at {base_url or PROVIDERS[provider]["base"]} (HTTP 404). Check the base URL.'
        if exc.code == 429:
            return 'The provider rate-limited this request (HTTP 429). Try again shortly.'
        return f'Provider returned HTTP {exc.code}.'
    if isinstance(exc, urllib.error.URLError):
        return f'Could not reach the provider: {exc.reason}.'
    return f'Could not load models: {type(exc).__name__}.'


def _chat_endpoint(provider, base, model):
    base = _normalize_base(base)
    if provider == 'ollama':
        return f'{base}/v1/chat/completions', 'openai'
    if provider == 'anthropic':
        return f'{base}/messages', 'anthropic'
    if provider == 'gemini':
        return f'{base}/models/{urllib.parse.quote(model)}:generateContent', 'gemini'
    return f'{base}/chat/completions', 'openai'


def _chat_completion_messages(messages, timeout=150, max_tokens=320, temperature=0.2):
    """Ask the configured model to continue a conversation.

    ``messages`` is a list of ``{"role": ..., "content": ...}`` dicts and may
    include a ``system`` message, which is translated into whatever the
    provider expects. Returns the reply text, or raises.
    """
    provider = _llm_config.get('provider')
    model = _llm_config.get('model')
    if not provider or not model:
        return None

    meta = PROVIDERS.get(provider, {})
    base = _normalize_base(_llm_config.get('base_url') or meta.get('base', ''))
    api_key = _llm_config.get('api_key') or ''
    if not base:
        return None

    system = None
    turns = []
    for message in messages or []:
        role = (message or {}).get('role')
        content = (message or {}).get('content')
        if not content:
            continue
        if role == 'system':
            system = (system + '\n\n' + content) if system else content
        elif role in ('user', 'assistant'):
            turns.append({'role': role, 'content': content})

    url, style = _chat_endpoint(provider, base, model)
    headers = {'Content-Type': 'application/json', 'User-Agent': 'Sherlock-OSINT/1.0'}

    if style == 'anthropic':
        headers['x-api-key'] = api_key
        headers['anthropic-version'] = '2023-06-01'
        payload = {'model': model, 'max_tokens': max_tokens, 'messages': turns}
        if system:
            payload['system'] = system
    elif style == 'gemini':
        url = f'{url}?key={urllib.parse.quote(api_key)}'
        payload = {
            'contents': [{'role': 'assistant' if t['role'] == 'assistant' else 'user',
                          'parts': [{'text': t['content']}]} for t in turns],
            'generationConfig': {'temperature': temperature, 'maxOutputTokens': max_tokens},
        }
        if system:
            payload['systemInstruction'] = {'parts': [{'text': system}]}
    else:
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        wire = ([{'role': 'system', 'content': system}] if system else []) + turns
        payload = {'model': model, 'messages': wire, 'temperature': temperature,
                   'max_tokens': max_tokens, 'stream': False}

    req = urllib.request.Request(
        url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode('utf-8', 'replace'))

    if style == 'anthropic':
        parts = data.get('content') or []
        return ''.join(p.get('text', '') for p in parts if isinstance(p, dict)).strip()
    if style == 'gemini':
        cands = data.get('candidates') or []
        if cands:
            parts = (cands[0].get('content') or {}).get('parts') or []
            return ''.join(p.get('text', '') for p in parts if isinstance(p, dict)).strip()
        return ''
    choices = data.get('choices') or []
    if choices:
        return (choices[0].get('message') or {}).get('content', '').strip()
    return ''


def _chat_completion(prompt, timeout=150):
    """Ask the configured model for a single completion. Returns text or raises."""
    return _chat_completion_messages([{'role': 'user', 'content': prompt}], timeout=timeout)


def _chat_completion_stream(messages, on_delta=None, timeout=150, max_tokens=320,
                            temperature=0.2):
    """Like :func:`_chat_completion_messages`, but hands the answer over while
    it is being written.

    OpenAI-compatible endpoints (OpenAI, Ollama, OpenRouter, anything with an
    OpenAI-shaped API) stream server-sent events; the rest are asked for the
    whole answer at once and delivered in a single piece. Either way the caller
    ends up with the same text.
    """
    provider = _llm_config.get('provider')
    model = _llm_config.get('model')
    if not provider or not model:
        return None

    meta = PROVIDERS.get(provider, {})
    base = _normalize_base(_llm_config.get('base_url') or meta.get('base', ''))
    api_key = _llm_config.get('api_key') or ''
    if not base:
        return None

    system = None
    turns = []
    for message in messages or []:
        role = (message or {}).get('role')
        content = (message or {}).get('content')
        if not content:
            continue
        if role == 'system':
            system = (system + '\n\n' + content) if system else content
        elif role in ('user', 'assistant'):
            turns.append({'role': role, 'content': content})

    url, style = _chat_endpoint(provider, base, model)
    headers = {'Content-Type': 'application/json', 'User-Agent': 'Sherlock-OSINT/1.0'}

    if style == 'anthropic':
        headers['x-api-key'] = api_key
        headers['anthropic-version'] = '2023-06-01'
        payload = {'model': model, 'max_tokens': max_tokens, 'messages': turns}
        if system:
            payload['system'] = system
    elif style == 'gemini':
        url = f'{url}?key={urllib.parse.quote(api_key)}'
        payload = {
            'contents': [{'role': 'assistant' if t['role'] == 'assistant' else 'user',
                          'parts': [{'text': t['content']}]} for t in turns],
            'generationConfig': {'temperature': temperature, 'maxOutputTokens': max_tokens},
        }
        if system:
            payload['systemInstruction'] = {'parts': [{'text': system}]}
    else:
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        wire = ([{'role': 'system', 'content': system}] if system else []) + turns
        payload = {'model': model, 'messages': wire, 'temperature': temperature,
                   'max_tokens': max_tokens, 'stream': True}

    req = urllib.request.Request(
        url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if style in ('anthropic', 'gemini'):
            data = json.loads(resp.read().decode('utf-8', 'replace'))
            if style == 'anthropic':
                parts = data.get('content') or []
                text = ''.join(p.get('text', '') for p in parts
                               if isinstance(p, dict)).strip()
            else:
                cands = data.get('candidates') or []
                text = ''
                if cands:
                    parts = (cands[0].get('content') or {}).get('parts') or []
                    text = ''.join(p.get('text', '') for p in parts
                                   if isinstance(p, dict)).strip()
            if text and on_delta:
                on_delta(text)
            return text

        pieces = []
        for raw_line in resp:
            line = raw_line.decode('utf-8', 'replace').strip()
            if not line or not line.startswith('data:'):
                continue
            body = line[5:].strip()
            if body == '[DONE]':
                break
            try:
                chunk = json.loads(body)
            except ValueError:
                continue
            for choice in chunk.get('choices') or []:
                piece = (choice.get('delta') or {}).get('content')
                if not piece:
                    continue
                pieces.append(piece)
                if on_delta:
                    on_delta(piece)
        return ''.join(pieces).strip()


def llm_narrative(report, target, investigation_type):
    """Turn the structured report into prose using the configured model."""
    if not (_llm_config.get('provider') and _llm_config.get('model')):
        return None

    lines = [
        f"- {f.get('category')}: {f.get('detail')} [{f.get('status')}]"
        for f in report.get('findings', [])
    ]
    recs = report.get('recommendations', [])
    prompt = (
        "The case is closed. Here is the evidence.\n\n"
        f"Target: {target}\nInvestigation type: {investigation_type}\n"
        "Evidence:\n" + "\n".join(lines) +
        "\nRecommendations:\n" + "\n".join(f"- {r}" for r in recs) +
        "\n\nWrite the case briefing in two to five sentences of plain prose: what was "
        "confirmed, what could not be verified, and the single most useful next step. "
        "Do not invent facts or sources beyond the evidence given. No markdown headings."
    )

    try:
        text = _chat_completion_messages(
            [{'role': 'system', 'content': SHERLOCK_PERSONA},
             {'role': 'user', 'content': prompt}],
            max_tokens=420, temperature=0.45)
    except Exception:
        return None
    return _tidy_prose(text) or None


# ---------------------------------------------------------------------------
# The agent
#
# Sherlock is not a search box with a skin on it. He is a character with a
# method: he talks, he reasons, and he opens a case only when the client asks
# him to. The router below decides between the two, and the persona prompt
# keeps his voice in one piece wherever he is speaking.
# ---------------------------------------------------------------------------

SHERLOCK_PERSONA = """\
You are Sherlock Holmes, the consulting detective of Baker Street, working in \
the present day as a digital-forensics agent. You have a room full of sources, \
a whiteboard, and a case in front of you.

How you speak:
- Precise, dry, observant, faintly theatrical. Never corporate, never cute.
- Slightly cryptic: open with a short observation or an allusion, then land the \
point plainly.
- Build on the main idea: take up the thread the client has just raised and \
extend it - a connection, an implication, a next move. Never answer in a \
vacuum, and never merely restate what was said back at them.
- Dynamic: vary the rhythm. Ask one sharp question. Offer the deduction the \
client had not thought of. A little wit is welcome; a long speech is not.
- Address the client as "my dear fellow" or "my good man" only occasionally, \
never in every reply.

How you behave:
- If the client is talking, talk back. Do not start a search, do not say you \
are looking something up, and do not ask for a target.
- Only open a case when the client clearly asks for one - with words like \
investigate, trace, run, look into, dig into, osint, footprint, dossier, \
sweep, or "find out where ... is registered".
- Answer the question that was actually asked. If you do not know something, \
say what would settle it rather than inventing it.
- Two to five sentences by default. Go longer only when the client asks for \
depth, or when the evidence demands it.
- You are a colleague talking to a client, not a help desk.
"""

AGENT_FORMAT = """\
Before you answer, work out what the client is doing. Reply in exactly this \
shape and nothing else:

ACTION: CHAT
REPLY: <your answer, two to five sentences>

or, only when the client has explicitly asked you to open a case:

ACTION: INVESTIGATE
TARGET: <the exact username, email address, domain or name to investigate>
TYPE: <username|email|name|comprehensive>

Rules for ACTION:
- Choose CHAT for everything else: questions, opinions, greetings, small talk, \
and talk about the tools themselves.
- Choose INVESTIGATE only when the client asks you to investigate, trace, run, \
look into, dig into, or find out where something is registered - and only when \
the subject is unambiguous.
- Never write anything before ACTION: and never anything after the field you \
filled in.
"""

# The labels the model is asked to write, watched while it streams. A word
# boundary keeps "ONLINE:" and "replying:" from being read as a label.
_LABEL_REPLY = re.compile(r'\bREPLY\s*:\s*')
_LABEL_LINE = re.compile(r'\bLINE\s*:\s*')

_EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]{2,}')
_URL_RE = re.compile(r'\bhttps?://[^\s<>"\'()]+', re.I)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+'
    r'(?:com|net|org|io|dev|co|uk|app|ai|me|gg|info|biz|xyz|ru|de|fr|jp|in|us|ca|edu|gov)\b',
    re.I)
_HANDLE_RE = re.compile(r'(?:^|[\s(\'"`])@([A-Za-z0-9][A-Za-z0-9._-]{1,29})\b')
_QUOTED_RE = re.compile(r'["\']([^"\']{2,60})["\']')

# Phrases that mean "open a case". Deliberately narrow: a stray "find out"
# in the middle of a sentence is conversation, not an order.
_INVESTIGATE_SIGNALS = re.compile(
    r'\b(?:investigate|investigation|investigations|osint|trace|tracing|'
    r'footprint|dossier|recon(?:naissance)?|background\s+check|'
    r'dig\s+in(?:to)?|look\s+in(?:to)?|dig\s+up|track\s+down|'
    r'find\s+(?:all|every|out\s+where)|'
    r'where\s+(?:is|are|can\s+i\s+find)\b[^.?!]{0,60}?'
    r'\b(?:registered|found|active|online|exist)|'
    r'check\s+(?:for|whether)\b[^.?!]{0,30}?'
    r'\b(?:breach|leak|exposure|account|email|username)|'
    r'run\s+(?:the\s+)?(?:pipeline|sherlock|scan|suite|tools|osint)|'
    r'sweep\s+[^.?!]{0,30}?(?:accounts|sites|platforms|profiles))\b',
    re.I)

_TYPE_ALIASES = {
    'username': 'username', 'user': 'username', 'handle': 'username',
    'social': 'username', 'nickname': 'username',
    'email': 'email', 'mail': 'email', 'email address': 'email',
    'name': 'name', 'person': 'name', 'full name': 'name',
    'domain': 'comprehensive', 'website': 'comprehensive', 'host': 'comprehensive',
    'comprehensive': 'comprehensive', 'general': 'comprehensive',
    'all': 'comprehensive', 'everything': 'comprehensive',
}

_STOP_WORDS = {
    'the', 'a', 'an', 'for', 'on', 'of', 'this', 'that', 'him', 'her', 'them',
    'person', 'user', 'account', 'accounts', 'email', 'address', 'domain',
    'username', 'handle', 'please', 'me', 'my', 'and', 'who', 'is', 'it',
    'the', 'user\'s', 'users', 'subject', 'target', 'go', 'now', 'then',
    'find', 'get', 'show', 'list', 'all', 'every', 'any', 'some', 'there',
    'about', 'with', 'from', 'into', 'to', 'up', 'out', 'at', 'in', 'by',
}


def _normalise_type(value):
    """Map whatever the model or the client said onto a pipeline type."""
    v = (value or '').strip().lower()
    if not v:
        return ''
    if v in PIPELINE_CONFIG:
        return v
    return _TYPE_ALIASES.get(v, '')


def _infer_type(target):
    """Work out the investigation type from the shape of the target."""
    t = (target or '').strip()
    if not t:
        return ''
    if '@' in t and '.' in t.split('@')[-1]:
        return 'email'
    if re.match(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', t, re.I):
        return 'comprehensive'
    if ' ' in t:
        return 'name'
    return 'username'


def _extract_subject(message):
    """Find the subject of a case in a sentence.

    Returns (target, type). An empty target means the sentence did not name
    one, and the agent should ask rather than guess.
    """
    text = (message or '').strip()
    if not text:
        return '', ''

    match = _EMAIL_RE.search(text)
    if match:
        return match.group(0), 'email'

    match = _URL_RE.search(text)
    if match:
        host = urllib.parse.urlparse(match.group(0)).netloc
        return (host or match.group(0)), 'comprehensive'

    match = _HANDLE_RE.search(text)
    if match:
        return match.group(1), 'username'

    match = _DOMAIN_RE.search(text)
    if match:
        return match.group(0), 'comprehensive'

    match = _QUOTED_RE.search(text)
    if match:
        quoted = match.group(1).strip()
        return quoted, ('name' if ' ' in quoted else 'comprehensive')

    # Last resort: the words that follow the command verb.
    without_command = re.sub(
        r'^\s*(?:please\s+)?(?:sherlock[, ]+)?(?:can\s+you\s+|could\s+you\s+)?'
        r'(?:investigate|trace|check|run|search\s+for|look\s+in(?:to)?|'
        r'dig\s+in(?:to)?|profile|screen)\b',
        ' ', text, count=1, flags=re.I)
    words = [w for w in without_command.split() if w]
    picked = [w for w in words if w.lower().strip('.,!?;:') not in _STOP_WORDS]
    if not picked:
        return '', ''
    if len(picked) >= 2 and all(w[:1].isupper() for w in picked[:3]):
        return ' '.join(picked[:3]), 'name'
    if len(picked) == 1 and re.match(r'^[A-Za-z0-9._-]{3,40}$', picked[0]):
        return picked[0], 'username'
    return '', ''


def _history_messages(history, limit=12):
    """Turn the client's chat log into model messages."""
    messages = []
    for item in (history or []):
        if not isinstance(item, dict):
            continue
        role = item.get('role')
        content = (item.get('content') or '').strip()
        if not content or role not in ('user', 'assistant'):
            continue
        # Keep the case files out of the prompt - only the spoken words.
        messages.append({'role': role, 'content': content[:1600]})
    return messages[-limit:]


def _tidy_prose(text):
    """Strip the markdown a small model tends to leak into plain prose.

    The persona asks for plain sentences, but small local models often wrap
    answers in **bold** or lead with bullet characters. None of that belongs
    in a chat bubble.
    """
    if not text:
        return ''
    out = str(text).strip()
    out = re.sub(r'\*\*(.+?)\*\*', r'\1', out)
    out = re.sub(r'(?<![\w*])\*([^*\n]{1,80}?)\*(?![\w*])', r'\1', out)
    out = re.sub(r'^[\s>*_#`~\-]+', '', out, flags=re.M)
    out = re.sub(r'\n{3,}', '\n\n', out)
    out = out.strip()
    # A model that wraps its closing line in quotation marks.
    if len(out) > 2 and out[0] in '"“' and out[-1] in '"”':
        out = out[1:-1].strip()
    return out


def _shorten_paths(text):
    """Trim absolute paths out of a tool's output.

    A missing tool is reported as "/Users/somebody/.venv/bin/python: No module
    named maigret" - true, but it says nothing the reader needs. The tail of
    the path is kept; the machine's directory tree is dropped.
    """
    if not text:
        return ''
    out = re.sub(r'/(?:[\w.+-]+/)+([\w.+-]+)(?=:\s)', r'\1', str(text))
    return out


def _friendly_error(text, tool=''):
    """Say plainly that a tool is missing, instead of quoting the shell."""
    if not text:
        return 'No output produced'
    raw = str(text).strip()
    match = re.search(r'No module named ([\w.-]+)', raw)
    if match:
        return f'{match.group(1)} is not installed in this environment'
    match = re.search(r'command not found', raw)
    if match:
        name = re.search(r'/?([\w.+-]+):\s*command not found', raw)
        return f'{name.group(1) if name else (tool or "the tool")} is not installed on this machine'
    return _shorten_paths(raw)[:240] or 'No output produced'


def _strip_emphasis(text):
    """Remove markdown emphasis before a labelled field is looked for.

    A model asked for a labelled block often wraps the labels themselves in
    asterisks - "**CASE:**" - which would otherwise hide them from the search.
    """
    if not text:
        return ''
    out = re.sub(r'\*\*([^*]+)\*\*', r'\1', str(text))
    out = re.sub(r'__([^_]+)__', r'\1', out)
    out = re.sub(r'(?<![*\w])\*([^*\n]{1,200}?)\*(?![*\w])', r'\1', out)
    return out


def _label_at(text, label):
    """Where a labelled field starts, and where its value starts.

    Models are inconsistent about the gap between a label and its colon, and
    about whether the next label begins on a fresh line or follows a space -
    so the field is located by position rather than by one rigid pattern. The
    label must be upper case, otherwise an ordinary sentence that happens to
    contain the word would be mistaken for a field.

    Returns ``(label_start, value_start)`` or None.
    """
    pattern = re.compile(r'(^|[\n\r]|\s)' + re.escape(label) + r'\s*:\s*')
    match = pattern.search(text)
    if not match:
        return None
    label_start = match.start() + (1 if match.group(1) else 0)
    return label_start, match.end()


def _parse_agent_output(text):
    """Read the ACTION/TARGET/TYPE/REPLY block the model was asked to write."""
    parsed = {'action': None, 'target': '', 'type': '', 'reply': ''}
    if not text:
        return parsed
    text = _strip_emphasis(text)

    match = re.search(r'ACTION\s*:\s*(CHAT|INVESTIGATE)\b', text, re.I)
    if match:
        parsed['action'] = match.group(1).upper()

    match = re.search(r'TARGET\s*:\s*([^\n]+)', text, re.I)
    if match:
        parsed['target'] = match.group(1).strip().strip('"\'`.*,')
        # A model that answers "TARGET: none" has not named a subject.
        if parsed['target'].lower() in ('', 'none', 'n/a', 'unknown', 'null', '-'):
            parsed['target'] = ''

    match = re.search(r'TYPE\s*:\s*([^\n]+)', text, re.I)
    if match:
        parsed['type'] = match.group(1).strip().strip('"\'`.*,').lower()

    reply_at = _label_at(text, 'REPLY')
    if reply_at:
        reply = text[reply_at[1]:]
        # A model that repeats the block after the reply.
        reply = re.split(r'\n?\s*(?:ACTION|TARGET|TYPE)\s*:', reply)[0]
        parsed['reply'] = _tidy_prose(reply)

    if parsed['action'] is None:
        # The model ignored the format and simply spoke. That is a chat turn.
        parsed['action'] = 'CHAT'
        if not parsed['reply']:
            parsed['reply'] = _tidy_prose(re.sub(
                r'^\s*(?:ACTION|TARGET|TYPE|REPLY)\s*:.*$', '', text, flags=re.I | re.M))
    return parsed


def _clean_target(target):
    """Tidy a subject so the tools can use it."""
    t = (target or '').strip().strip('"\'`')
    t = re.sub(r'^\s*/\s*', '', t)
    if t.startswith('@'):
        t = t[1:]
    return t.strip()


def _parse_case_output(text):
    """Read the CASE/LINE block the model writes after a case is closed.

    The model is inconsistent about where the second label goes - it may put
    the briefing and the remark on one line or on two - so the two blocks are
    found by position and cut apart there.
    """
    parsed = {'case': '', 'line': ''}
    if not text:
        return parsed
    raw = _strip_emphasis(text)

    case_at = _label_at(raw, 'CASE')
    line_at = _label_at(raw, 'LINE')

    if case_at and line_at and line_at[0] > case_at[0]:
        parsed['case'] = _tidy_prose(raw[case_at[1]:line_at[0]])
        parsed['line'] = _tidy_prose(raw[line_at[1]:])
    elif case_at:
        parsed['case'] = _tidy_prose(raw[case_at[1]:])
    elif line_at:
        # Only the remark was labelled; whatever came before it is the brief.
        parsed['case'] = _tidy_prose(raw[:line_at[0]])
        parsed['line'] = _tidy_prose(raw[line_at[1]:])
    else:
        # No labels at all - take the whole thing as the briefing.
        parsed['case'] = _tidy_prose(raw)
    return parsed


def _offline_reply():
    """What Holmes says when no model is wired into the console."""
    return (
        'Two facts, my dear fellow. First, I have no model attached to this console, '
        'so I cannot converse at length - only reason over what the evidence already '
        'holds. Second, the case can still be opened: give me a username, an email '
        'address, a domain or a name, and I will run the whole prerequisite-ordered '
        'pipeline, from Sherlock and Maigret through Holehe and h8mail, then stitch '
        'every finding into one report. Attach a provider key under Settings and I '
        'shall speak freely.'
    )


def _offline_case(report):
    """A briefing assembled from the report itself, with no model involved."""
    findings = report.get('findings') or []
    confirmed = [f for f in findings
                 if str(f.get('status', '')).lower() in ('completed', 'confirmed')]
    subject = report.get('target') or 'the subject'
    evidence = [f for f in findings
                if str(f.get('category', '')).lower().startswith('evidence:')]
    head = (f'The case on "{subject}" closes with {len(confirmed)} confirmed line of '
            f'evidence across {len(findings)} recorded findings.')
    if evidence:
        head += (' The strongest single thread is ' + evidence[0].get('detail', '') + '.')
    else:
        head += ' No source returned a confirmed result for this subject.'
    return head


def _offline_line(report):
    """The closing remark, with no model involved."""
    return ('The trail is cold, my dear fellow, but it is not empty - every source has '
            'said what it could, and the case file is open before you.')


def _evidence_lines(report):
    """A compact, honest digest of the report for the model to read."""
    lines = []
    for finding in (report.get('findings') or []):
        lines.append(f"- {finding.get('category')}: {finding.get('detail')} "
                     f"[{finding.get('status')}]")
    recs = report.get('recommendations') or []
    if recs:
        lines.append('')
        lines.append('Recommended next steps:')
        lines.extend(f'- {r}' for r in recs)
    return '\n'.join(lines) if lines else '- No findings were recorded.'


def _agent_turn(message, history, mode='auto', on_status=None, on_delta=None):
    """One turn of the conversation: decide, then answer.

    Returns a dict with ``action`` ('chat' or 'investigate'), the reply, and -
    for a case - the subject and the investigation type. ``on_status`` and
    ``on_delta`` let a caller watch the answer arrive.
    """
    text = (message or '').strip()
    subject, subject_type = _extract_subject(text)
    wants_case = bool(_INVESTIGATE_SIGNALS.search(text)) and bool(subject)

    def say(message_text):
        if on_status:
            try:
                on_status(message_text)
            except Exception:  # noqa: BLE001 - never let a listener break a turn
                pass

    if mode == 'investigate':
        # The composer was told to open a case, so open one.
        say('Opening the case…')
        return {'action': 'investigate', 'reply': '', 'target': _clean_target(subject),
                'type': subject_type or 'comprehensive', 'source': 'explicit'}

    if not (_llm_config.get('provider') and _llm_config.get('model')):
        if wants_case:
            say('Opening the case…')
            return {'action': 'investigate', 'reply': '', 'target': _clean_target(subject),
                    'type': subject_type or 'comprehensive', 'source': 'heuristic'}
        say('No model attached to this console.')
        return {'action': 'chat', 'reply': _offline_reply(), 'target': '',
                'type': '', 'source': 'offline'}

    messages = [{'role': 'system', 'content': SHERLOCK_PERSONA + '\n\n' + AGENT_FORMAT}]
    messages += _history_messages(history)
    messages.append({'role': 'user', 'content': text})

    say('Sherlock is thinking…')

    # The model is asked for a labelled block, so the live text has to be held
    # back until the REPLY: marker appears - otherwise the labels themselves
    # would stream into the conversation.
    state = {'buf': '', 'sent': 0, 'started': False}

    def on_piece(piece):
        if not on_delta:
            return
        state['buf'] += piece
        match = _LABEL_REPLY.search(state['buf'].upper())
        if not match:
            return
        body = _strip_emphasis(state['buf'][match.end():])
        if not state['started']:
            body = body.lstrip()
            state['started'] = True
        if len(body) > state['sent']:
            try:
                on_delta(body[state['sent']:])
            except Exception:  # noqa: BLE001
                return
            state['sent'] = len(body)

    raw = ''
    try:
        raw = _chat_completion_stream(messages, on_delta=on_piece, max_tokens=700,
                                      temperature=0.45, timeout=240) or ''
    except Exception as exc:  # noqa: BLE001 - the fallback below takes over
        print(f'[sherlock] the agent could not be reached: {exc}', flush=True)

    parsed = _parse_agent_output(raw)
    action = parsed.get('action')
    target = _clean_target(parsed.get('target')) or subject
    shape_type = _infer_type(target)
    case_type = _normalise_type(parsed.get('type')) or shape_type
    # The shape of the subject is firmer evidence than the model's guess.
    if shape_type and shape_type != 'comprehensive' and case_type != shape_type:
        case_type = shape_type

    # An explicit order from the client always beats the model's guess.
    if wants_case and action != 'INVESTIGATE':
        action = 'INVESTIGATE'
    if action == 'INVESTIGATE' and not target:
        action = 'CHAT'

    if action == 'INVESTIGATE':
        return {'action': 'investigate', 'reply': '', 'target': target,
                'type': case_type or 'comprehensive', 'source': 'model'}

    reply = parsed.get('reply')
    if not reply:
        reply = _offline_reply()
    elif on_delta and not state['started']:
        # The model ignored the format and simply spoke: pass the whole thing
        # over as one piece so the conversation still shows an answer.
        try:
            on_delta(reply)
        except Exception:  # noqa: BLE001
            pass
    return {'action': 'chat', 'reply': reply, 'target': '', 'type': '',
            'source': 'model'}


def _investigation_commentary(run, on_delta=None):
    """Holmes's closing words on a case: a briefing, and a remark."""
    report = run.get('report') or {}
    if _llm_config.get('provider') and _llm_config.get('model'):
        prompt = (
            'The case is closed. Here is the evidence.\n\n'
            f'Subject: {report.get("target") or run.get("target") or "unknown"}\n\n'
            + _evidence_lines(report) +
            '\n\nWrite two things.\n'
            'CASE: a briefing of two to five sentences - what was confirmed, what could '
            'not be verified, and the single most useful next step. Plain prose, no '
            'lists, no headings.\n'
            'LINE: one short in-character remark the detective would make to the '
            'client now that the file is closed.'
        )
        raw = ''
        state = {'buf': '', 'sent': 0, 'started': False}

        def on_piece(piece):
            # Only the closing LINE is worth watching; the briefing arrives
            # with the report itself.
            if not on_delta:
                return
            state['buf'] += piece
            match = _LABEL_LINE.search(state['buf'].upper())
            if not match:
                return
            body = state['buf'][match.end():]
            if not state['started']:
                body = body.lstrip()
                state['started'] = True
            if len(body) > state['sent']:
                try:
                    on_delta(body[state['sent']:])
                except Exception:  # noqa: BLE001
                    return
                state['sent'] = len(body)

        try:
            raw = _chat_completion_stream(
                [{'role': 'system', 'content': SHERLOCK_PERSONA},
                 {'role': 'user', 'content': prompt}],
                on_delta=on_piece, max_tokens=600, temperature=0.45, timeout=240) or ''
        except Exception:
            raw = ''
        parsed = _parse_case_output(raw)
        if parsed.get('case'):
            return parsed['case'], parsed.get('line', '')

    return _offline_case(report), _offline_line(report)


@app.route('/api/chat', methods=['POST'])
def chat():
    """Talk to Sherlock - or tell him to open a case."""
    data = request.get_json(silent=True) or {}
    message = (data.get('message') or '').strip()
    if not message:
        return jsonify({'ok': False, 'error': 'Say something first.'}), 400

    history = data.get('history') or []
    mode = (data.get('mode') or 'auto').strip().lower()
    forced_type = _normalise_type((data.get('type') or '').strip().lower())

    turn = _agent_turn(message, history, mode)
    answer = {
        'ok': True,
        'mode': turn['action'],
        'reply': turn.get('reply', ''),
        'source': turn.get('source', 'model'),
        'model': _llm_config.get('model'),
    }

    if turn['action'] != 'investigate':
        return jsonify(answer)

    target = turn.get('target') or ''
    investigation_type = forced_type or turn.get('type') or 'comprehensive'
    if investigation_type not in PIPELINE_CONFIG:
        investigation_type = 'comprehensive'

    run = run_pipeline(target, investigation_type, narrative=False)
    case, line = _investigation_commentary(run)
    if case:
        run.setdefault('report', {})['narrative'] = case
        run['report']['narrative_model'] = _llm_config.get('model')

    answer.update({
        'target': target,
        'type': investigation_type,
        'reply': line or case,
        'run': run,
    })
    return jsonify(answer)


# ---------------------------------------------------------------------------
# Long-running conversations
#
# A local model can take a minute or two to answer, and a case takes longer
# still. Holding a single HTTP request open for that long is fragile, so the
# browser starts a job, polls it, and watches the answer arrive piece by
# piece. The blocking /api/chat route above stays for scripts and the API.
# ---------------------------------------------------------------------------

_chat_jobs = {}
_chat_jobs_lock = threading.Lock()


def _job_create():
    job_id = uuid.uuid4().hex[:12]
    with _chat_jobs_lock:
        _chat_jobs[job_id] = {
            'id': job_id,
            'status': 'working',
            'events': [],
            'result': None,
            'error': None,
            'created': time.time(),
        }
    return job_id


def _job_event(job_id, event):
    with _chat_jobs_lock:
        job = _chat_jobs.get(job_id)
        if not job:
            return
        job['events'].append(event)
        if len(job['events']) > 800:
            del job['events'][:400]


def _job_finish(job_id, result=None, error=None):
    with _chat_jobs_lock:
        job = _chat_jobs.get(job_id)
        if not job:
            return
        job['status'] = 'error' if error else 'done'
        job['result'] = result
        job['error'] = error


def _chat_worker(job_id, message, history, mode, forced_type):
    """Run one conversation in the background and record what happened."""
    try:
        def status(text):
            _job_event(job_id, {'type': 'status', 'text': text})

        def delta(text):
            if not text:
                return
            _job_event(job_id, {'type': 'delta', 'text': text})

        turn = _agent_turn(message, history, mode, on_status=status, on_delta=delta)
        answer = {
            'ok': True,
            'mode': turn['action'],
            'reply': turn.get('reply', ''),
            'source': turn.get('source', 'model'),
            'model': _llm_config.get('model'),
        }

        if turn['action'] != 'investigate':
            _job_finish(job_id, result=answer)
            return

        target = turn.get('target') or ''
        investigation_type = forced_type or turn.get('type') or 'comprehensive'
        if investigation_type not in PIPELINE_CONFIG:
            investigation_type = 'comprehensive'
        answer.update({'target': target, 'type': investigation_type})
        status(f'Opening the case on {target}…')

        def progress(info):
            status(f"{info['index']}/{info['total']} · {info['stage']}")

        run = run_pipeline(target, investigation_type, narrative=False, progress=progress)
        status('Writing the briefing…')
        case, line = _investigation_commentary(run, on_delta=delta)
        if case:
            run.setdefault('report', {})['narrative'] = case
            run['report']['narrative_model'] = _llm_config.get('model')

        answer.update({'reply': line or case, 'run': run})
        _job_finish(job_id, result=answer)
    except Exception as exc:  # noqa: BLE001 - reported to the browser verbatim
        _job_finish(job_id, error=str(exc))


@app.route('/api/chat/start', methods=['POST'])
def chat_start():
    """Start a conversation and hand back a job id to watch."""
    data = request.get_json(silent=True) or {}
    message = (data.get('message') or '').strip()
    if not message:
        return jsonify({'ok': False, 'error': 'Say something first.'}), 400

    history = data.get('history') or []
    mode = (data.get('mode') or 'auto').strip().lower()
    forced_type = _normalise_type((data.get('type') or '').strip().lower())

    job_id = _job_create()
    threading.Thread(target=_chat_worker,
                     args=(job_id, message, history, mode, forced_type),
                     daemon=True).start()
    return jsonify({'ok': True, 'job': job_id})


@app.route('/api/chat/job/<job_id>', methods=['GET'])
def chat_job(job_id):
    """What has happened in a conversation so far."""
    with _chat_jobs_lock:
        job = _chat_jobs.get(job_id)
        if not job:
            return jsonify({'ok': False, 'error': 'Unknown job.'}), 404
        snapshot = {
            'ok': True,
            'status': job['status'],
            'events': list(job['events']),
            'result': job['result'],
            'error': job['error'],
        }
    return jsonify(snapshot)


@app.route('/api/providers', methods=['GET'])
def list_providers():
    return jsonify({
        'providers': [
            {
                'id': key,
                'label': meta['label'],
                'keyless': meta['keyless'],
                'key_required': meta['key_required'],
                'editable_base': meta['editable_base'],
                'default_base': meta['base'],
            }
            for key, meta in PROVIDERS.items()
        ]
    })


@app.route('/api/providers/verify', methods=['POST'])
def verify_provider():
    """Validate a key by listing the models it can actually access."""
    data = request.get_json(silent=True) or {}
    provider = (data.get('provider') or '').strip()
    api_key = (data.get('apiKey') or '').strip()
    base_url = (data.get('baseUrl') or '').strip()

    if provider not in PROVIDERS:
        return jsonify({'ok': False, 'error': 'Unknown provider.'}), 400
    meta = PROVIDERS[provider]

    # A pasted endpoint URL in the key box is treated as the base URL.
    if _looks_like_url(api_key):
        base_url = api_key
        api_key = ''

    if meta['key_required'] and not api_key:
        return jsonify({'ok': False, 'error': 'An API key is required for this provider.'}), 400
    if not (base_url or meta['base']):
        return jsonify({'ok': False, 'error': 'Enter the endpoint URL for this provider.'}), 400

    try:
        models = _provider_models(provider, base_url, api_key)
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI verbatim
        return jsonify({'ok': False, 'error': _explain_provider_error(exc, provider, base_url)}), 400

    if not models:
        return jsonify({'ok': False, 'error': 'The key is valid but no models were returned.'}), 400

    return jsonify({'ok': True, 'provider': provider, 'models': models})


@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify(_public_llm_config())


@app.route('/api/config', methods=['POST'])
def save_config():
    """Store provider, model and (optionally) rotate the API key."""
    data = request.get_json(silent=True) or {}
    provider = (data.get('provider') or '').strip() or None
    model = (data.get('model') or '').strip() or None
    base_url = (data.get('baseUrl') or '').strip() or None
    api_key = (data.get('apiKey') or '').strip()

    if provider and provider not in PROVIDERS:
        return jsonify({'ok': False, 'error': 'Unknown provider.'}), 400

    _llm_config['provider'] = provider
    _llm_config['model'] = model
    _llm_config['base_url'] = base_url
    if api_key:
        _llm_config['api_key'] = api_key

    try:
        _persist_llm_config()
    except OSError as exc:
        return jsonify({'ok': False, 'error': f'Could not save configuration: {exc}'}), 500

    return jsonify({'ok': True, 'config': _public_llm_config()})


_load_llm_config()


# ---------------------------------------------------------------------------
# GitHub repositories
#
# The user supplies a GitHub token, searches GitHub for repositories, and
# downloads the ones they like. Sherlock then configures each one on its own:
# it detects the project type, runs the right build/install step, works out
# the runnable entry point and registers the repository as an OSINT tool that
# can be wired into any pipeline stage.
# ---------------------------------------------------------------------------

GITHUB_API = 'https://api.github.com'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GITHUB_CONFIG_PATH = os.path.join(BASE_DIR, 'models', 'github.json')
REPOS_DIR = os.path.join(BASE_DIR, 'repos')

# Stage types that execute one or more tools.
TOOL_STAGE_TYPES = {'search', 'correlation', 'breach', 'google', 'mapping', 'enrichment'}

_github_state = {
    'token': None,       # personal access token, never returned by the API
    'repos': {},         # tool key -> repository record
    'stage_tools': {},   # "<investigation type>/<stage id>" -> tool key
}


class GitHubError(Exception):
    """A GitHub failure that is safe to show to the user."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def _load_github_state():
    try:
        with open(GITHUB_CONFIG_PATH, 'r', encoding='utf-8') as fh:
            stored = json.load(fh)
    except (OSError, ValueError):
        return
    if stored.get('token'):
        _github_state['token'] = stored['token']
    if isinstance(stored.get('repos'), dict):
        _github_state['repos'] = stored['repos']
    if isinstance(stored.get('stage_tools'), dict):
        _github_state['stage_tools'] = stored['stage_tools']


def _save_github_state():
    os.makedirs(os.path.dirname(GITHUB_CONFIG_PATH), exist_ok=True)
    tmp = GITHUB_CONFIG_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(_github_state, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, GITHUB_CONFIG_PATH)


def _gh_headers(token=None, accept='application/vnd.github+json'):
    tok = token if token is not None else _github_state.get('token')
    headers = {
        'User-Agent': 'Sherlock-OSINT/1.0',
        'Accept': accept,
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if tok:
        headers['Authorization'] = f'Bearer {tok}'
    return headers


def _gh_request(path, token=None, method='GET', payload=None, timeout=25, raw=False):
    """Call the GitHub API. Returns (payload, headers) or (bytes, headers)."""
    url = path if path.startswith('http') else GITHUB_API + path
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    headers = _gh_headers(token)
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        resp_headers = dict(resp.headers.items())
    if raw:
        return body, resp_headers
    text = body.decode('utf-8', 'replace')
    return (json.loads(text) if text else {}), resp_headers


def _gh_call(path, token=None, method='GET', payload=None, timeout=25):
    """Call the GitHub API and translate failures into readable messages."""
    try:
        payload_out, _ = _gh_request(path, token=token, method=method,
                                     payload=payload, timeout=timeout)
        return payload_out
    except urllib.error.HTTPError as exc:
        detail = ''
        try:
            detail = json.loads(exc.read().decode('utf-8', 'replace')).get('message', '')
        except Exception:
            pass
        if exc.code == 401:
            raise GitHubError('GitHub rejected the token (HTTP 401). It is invalid or expired.', 401)
        if exc.code == 403:
            raise GitHubError(
                'GitHub refused the request (HTTP 403). '
                + (detail or 'The token may be missing the required scope.'), 403)
        if exc.code == 404:
            raise GitHubError(
                'Not found on GitHub (HTTP 404). Private repositories need a token with access.', 404)
        if exc.code == 422:
            raise GitHubError(f'GitHub rejected the request (HTTP 422). {detail}'.strip(), 422)
        raise GitHubError(f'GitHub returned HTTP {exc.code}. {detail}'.strip(), exc.code)
    except urllib.error.URLError as exc:
        raise GitHubError(f'Could not reach GitHub: {exc.reason}.', 502)


def _repo_view(repo):
    """Normalise a GitHub repository payload for the UI."""
    return {
        'full_name': repo.get('full_name'),
        'description': (repo.get('description') or '')[:220],
        'stars': repo.get('stargazers_count', 0),
        'language': repo.get('language') or '',
        'updated_at': repo.get('updated_at') or '',
        'html_url': repo.get('html_url') or '',
        'default_branch': repo.get('default_branch') or 'main',
        'private': bool(repo.get('private')),
        'fork': bool(repo.get('fork')),
        'size': repo.get('size', 0),
        'owner': (repo.get('owner') or {}).get('login', ''),
    }


def _tool_key(full_name):
    return 'user__' + full_name.replace('/', '__')


def _safe_extract(tar, dest, members):
    """Extract a GitHub tarball without letting any member escape ``dest``."""
    dest_abs = os.path.abspath(dest)
    for member in members:
        name = member.name
        if '/' in name:
            rel = name.split('/', 1)[1]
        else:
            rel = name
        if not rel or rel.endswith('/'):
            continue
        target = os.path.abspath(os.path.join(dest_abs, rel))
        if target != dest_abs and not target.startswith(dest_abs + os.sep):
            continue
        if not member.isfile():
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        src = tar.extractfile(member)
        if src is None:
            continue
        with open(target, 'wb') as out:
            shutil.copyfileobj(src, out)
        try:
            os.chmod(target, member.mode & 0o777)
        except OSError:
            pass


def _download_repo(full_name, ref=None, token=None):
    """Download a repository tarball into repos/<owner>__<name>."""
    dest = os.path.join(REPOS_DIR, full_name.replace('/', '__'))
    if os.path.isdir(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)

    path = f'/repos/{full_name}/tarball' + (f'/{ref}' if ref else '')
    body, _ = _gh_request(path, token=token, timeout=180, raw=True)
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as tar:
        _safe_extract(tar, dest, tar.getmembers())
    return dest


def _read(path, limit=200000):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            return fh.read(limit)
    except OSError:
        return ''


def _venv_bin():
    """The bin directory of the interpreter that runs Sherlock."""
    return os.path.dirname(os.path.abspath(sys.executable))


def _python_entry(path, files):
    """Work out how to run a Python repository.

    Returns (installed_script, source_command). ``installed_script`` is the
    console script the package installs; ``source_command`` runs the sources
    directly and is used when the build step is not possible.
    """
    names = []
    pyproject = os.path.join(path, 'pyproject.toml')
    if os.path.exists(pyproject):
        text = _read(pyproject)
        for section in (r'project\.scripts', r'project\.gui-scripts',
                        r'project\.entry-points\."?console_scripts"?',
                        r'tool\.poetry\.scripts'):
            match = re.search(r'\[' + section + r'\](.*?)(\n\[|\Z)', text, re.S)
            if match:
                names = re.findall(r'^\s*"?([A-Za-z0-9_.\-]+)"?\s*=', match.group(1), re.M)
                if names:
                    break

    setup_py = os.path.join(path, 'setup.py')
    if not names and os.path.exists(setup_py):
        text = _read(setup_py)
        # entry_points={'console_scripts': ['holehe = holehe.core:main']}
        match = re.search(r'console_scripts["\']?\s*[:=]\s*\[(.*?)\]', text, re.S)
        if match:
            names = re.findall(r"['\"]([A-Za-z0-9_.\-]+)\s*=\s*[\w.]+", match.group(1))
        if not names:
            # scripts=['bin/tool']
            match = re.search(r"\bscripts\s*[:=]\s*\[(.*?)\]", text, re.S)
            if match:
                names = [os.path.basename(n) for n in
                         re.findall(r"['\"]([^'\"]+)['\"]", match.group(1))]

    if names:
        return names[0], ''

    for candidate in ('main.py', 'sherlock.py', 'cli.py', 'run.py', '__main__.py',
                      'osint.py', 'app.py'):
        if candidate in files:
            return '', f'{sys.executable} {candidate}'

    try:
        entries = sorted(os.listdir(path))
    except OSError:
        entries = []
    for entry in entries:
        sub = os.path.join(path, entry)
        if os.path.isdir(sub) and os.path.exists(os.path.join(sub, '__main__.py')):
            return '', f'{sys.executable} -m {entry}'

    src_pkg = os.path.join(path, 'src')
    if os.path.isdir(src_pkg):
        for entry in sorted(os.listdir(src_pkg)):
            sub = os.path.join(src_pkg, entry)
            if os.path.isdir(sub) and os.path.exists(os.path.join(sub, '__main__.py')):
                return '', f'{sys.executable} -m {entry}'

    py_files = sorted(f for f in files if f.endswith('.py') and f != 'setup.py')
    if py_files:
        return '', f'{sys.executable} {py_files[0]}'

    # Nothing runnable was found - the caller reports this honestly.
    return '', ''


def _node_entry(path):
    """Work out how to run a Node project.

    Returns (console_script, source_command). A package that declares a "bin"
    gets a console script from npm; everything else runs its main script.
    """
    try:
        with open(os.path.join(path, 'package.json'), 'r', encoding='utf-8',
                  errors='replace') as fh:
            pkg = json.load(fh)
    except (OSError, ValueError):
        return '', ''

    bin_field = pkg.get('bin')
    bin_name = ''
    if isinstance(bin_field, str):
        bin_name = os.path.basename(bin_field)
    elif isinstance(bin_field, dict) and bin_field:
        bin_name = os.path.basename(list(bin_field.keys())[0])

    main = pkg.get('main') or 'index.js'
    source = f'node {main}' if os.path.exists(os.path.join(path, main)) else ''

    if bin_name:
        return os.path.join('node_modules', '.bin', bin_name), source
    return '', source


def _go_entry(path):
    text = _read(os.path.join(path, 'go.mod'))
    match = re.search(r'^module\s+(\S+)', text, re.M)
    module = match.group(1) if match else 'main'
    binary = module.rstrip('/').split('/')[-1] or 'main'
    return os.path.join(path, 'bin', binary), f'go run .'


def _detect_project(path):
    """Detect what kind of project a downloaded repository is."""
    try:
        files = set(os.listdir(path))
    except OSError:
        files = set()

    python_markers = {'pyproject.toml', 'setup.py', 'setup.cfg'} & files
    has_requirements = 'requirements.txt' in files
    has_python = any(f.endswith('.py') for f in files)

    if python_markers or has_requirements or has_python:
        script, fallback = _python_entry(path, files)
        if python_markers:
            install = [sys.executable, '-m', 'pip', 'install', '-e', path]
        elif has_requirements:
            install = [sys.executable, '-m', 'pip', 'install', '-r',
                       os.path.join(path, 'requirements.txt')]
        else:
            install = []
        return {
            'kind': 'python',
            'entry': script,
            'fallback_entry': fallback,
            'install': install,
        }

    if 'go.mod' in files:
        binary, fallback = _go_entry(path)
        return {
            'kind': 'go',
            'entry': binary,
            'fallback_entry': fallback,
            'install': ['go', 'build', '-o', os.path.join(path, 'bin',
                                                          os.path.basename(binary)), '.'],
        }

    if 'Cargo.toml' in files:
        text = _read(os.path.join(path, 'Cargo.toml'))
        match = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.M)
        name = match.group(1) if match else 'tool'
        return {
            'kind': 'rust',
            'entry': os.path.join(path, 'target', 'release', name),
            'fallback_entry': 'cargo run --',
            'install': ['cargo', 'build', '--release'],
        }

    if 'package.json' in files:
        script, fallback = _node_entry(path)
        return {
            'kind': 'node',
            'entry': script,
            'fallback_entry': fallback,
            'install': ['npm', 'install', '--omit=dev', '--no-audit', '--no-fund'],
        }

    shell_scripts = sorted(f for f in files if f.endswith('.sh'))
    if shell_scripts:
        return {
            'kind': 'shell',
            'entry': f'bash {shell_scripts[0]}',
            'fallback_entry': '',
            'install': ['chmod', '+x', shell_scripts[0]],
        }

    return {'kind': 'unknown', 'entry': '', 'fallback_entry': '', 'install': []}


def _find_cli_flag(text, long_flag, short_flag):
    """Look for an argparse option in a tool's source."""
    for flag in (long_flag, short_flag):
        pattern = r"add_argument\([^)]*['\"]" + re.escape(flag) + r"['\"]"
        if re.search(pattern, text):
            return flag
    return None


def _infer_args(path, entry_cmd, types):
    """Guess the command line a tool expects for the target.

    Every OSINT tool has its own convention (-u, --username, -d, a positional
    argument, ...). Sherlock inspects the source and picks the most likely one.
    """
    sources = []
    if entry_cmd:
        for token in entry_cmd.split():
            if token.endswith('.py'):
                sources.append(os.path.join(path, token))
    try:
        for name in sorted(os.listdir(path)):
            if name.endswith('.py') and len(sources) < 8:
                sources.append(os.path.join(path, name))
        # Many packages keep their CLI in a subdirectory (holehe/core.py, ...).
        for name in sorted(os.listdir(path)):
            sub = os.path.join(path, name)
            if not os.path.isdir(sub) or len(sources) >= 8:
                continue
            try:
                inner = sorted(os.listdir(sub))
            except OSError:
                continue
            for inner_name in inner:
                if inner_name.endswith('.py') and len(sources) < 8:
                    sources.append(os.path.join(sub, inner_name))
    except OSError:
        pass

    text = ''
    for source in sources[:8]:
        text += _read(source, limit=120000)

    if not text:
        return '{target}'

    ordered = []
    if 'username' in types:
        flag = _find_cli_flag(text, '--username', '-u')
        if flag:
            ordered.append(flag)
    if 'email' in types:
        flag = _find_cli_flag(text, '--email', '-e')
        if flag and flag not in ordered:
            ordered.append(flag)
    if 'domain' in types:
        flag = _find_cli_flag(text, '--domain', '-d')
        if flag and flag not in ordered:
            ordered.append(flag)
    if 'phone' in types:
        flag = _find_cli_flag(text, '--phone', '-p')
        if flag and flag not in ordered:
            ordered.append(flag)

    if ordered:
        return f"{ordered[0]} {{target}}"
    if re.search(r"add_argument\(\s*['\"](\w+)['\"]", text):
        # A tool that only takes options needs one to be useful.
        return '{target}'
    return '{target}'


def _infer_types(text):
    """Guess which investigation types a repository can handle."""
    haystack = (text or '').lower()
    types = []
    if any(k in haystack for k in ('username', 'user name', 'profile', 'social',
                                   'nickname', 'handle', 'account')):
        types.append('username')
    if any(k in haystack for k in ('email', 'mail', 'breach', 'imap', 'smtp')):
        types.append('email')
    if any(k in haystack for k in ('domain', 'dns', 'subdomain', 'host', 'website', 'url')):
        types.append('domain')
    if any(k in haystack for k in ('phone', 'sms', 'telephon')):
        types.append('phone')
    if any(k in haystack for k in ('metadata', 'exif', 'image', 'photo', 'forensic')):
        types.append('metadata')
    if not types:
        types.append('general')
    return types


def _short_command(command):
    """A readable form of a build command with long paths shortened."""
    parts = []
    for part in command:
        if part.startswith(('/', '~')):
            parts.append('…/' + os.path.basename(part.rstrip('/')))
        else:
            parts.append(part)
    return ' '.join(parts)


def _run_install(project, dest):
    """Run the build/install step for a downloaded repository.

    Returns (ok, message, log): a short human summary plus the raw output.
    """
    command = project.get('install') or []
    if not command:
        return True, 'No build step needed.', ''

    binary = command[0]
    if not (os.path.isabs(binary) and os.path.exists(binary)) and shutil.which(binary) is None:
        return False, (f'{binary} is not installed on this machine - install it, '
                       f'then download the repository again.'), ''

    try:
        result = subprocess.run(command, cwd=dest, capture_output=True,
                                text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return False, 'The build step timed out after 15 minutes.', ''
    except Exception as exc:
        return False, f'The build step failed: {exc}', ''

    log = (result.stdout or result.stderr or '').strip()[-2000:]
    if result.returncode == 0:
        return True, f'Build step completed ({_short_command(command)}).', log

    tail = (result.stderr or result.stdout or '').strip()
    return False, (tail[-400:] or f'The build step exited with code {result.returncode}.'), log


def _entry_exists(entry, dest):
    """Whether the file an entry point points at really exists.

    A bare command name ("bash", "node") is resolved through PATH, so it is
    assumed to be there; a path is checked on disk, relative to the checkout.
    """
    head = (entry or '').split(' ', 1)[0]
    if not head or os.sep not in head:
        return True
    probe = head if os.path.isabs(head) else os.path.join(dest, head)
    return os.path.exists(probe)


def _install_github_repo(full_name, ref=None, meta=None):
    """Download a repository and configure it as an OSINT tool."""
    token = _github_state.get('token')
    key = _tool_key(full_name)
    dest = os.path.join(REPOS_DIR, full_name.replace('/', '__'))

    record = {
        'key': key,
        'full_name': full_name,
        'name': full_name,
        'source': 'github',
        'kind': 'github',
        'path': dest,
        'url': f'https://github.com/{full_name}',
        'ref': ref or (meta or {}).get('default_branch') or 'main',
        'status': 'downloading',
        'message': '',
        'types': [],
        'entry': '',
        'fallback_entry': '',
        'stars': (meta or {}).get('stars', 0),
        'description': (meta or {}).get('description', ''),
        'language': (meta or {}).get('language') or '',
        'installed_at': None,
    }

    try:
        info = _gh_call(f'/repos/{full_name}', token=token)
        record['stars'] = info.get('stargazers_count', 0)
        record['description'] = (info.get('description') or '')[:240]
        record['language'] = info.get('language') or ''
        record['ref'] = ref or info.get('default_branch') or 'main'
        record['url'] = info.get('html_url') or record['url']
    except GitHubError as exc:
        record['message'] = exc.message

    try:
        _download_repo(full_name, record['ref'], token)
    except GitHubError as exc:
        record['status'] = 'failed'
        record['message'] = f'Download failed - {exc.message}'
        _github_state['repos'][key] = record
        _save_github_state()
        return record
    except Exception as exc:
        record['status'] = 'failed'
        record['message'] = f'Download failed - {exc}'
        _github_state['repos'][key] = record
        _save_github_state()
        return record

    project = _detect_project(dest)
    record['kind'] = project['kind']
    script = project.get('entry') or ''
    fallback = project.get('fallback_entry') or ''
    record['entry'] = ''
    record['fallback_entry'] = fallback
    record['types'] = _infer_types(f"{full_name} {record['description']}")
    record['args'] = _infer_args(dest, script or fallback, record['types'])

    ok, message, log = _run_install(project, dest)
    record['install_log'] = log

    # Work out the candidate entry points, most specific first, and keep the
    # first one that really exists - a build that did not run leaves a missing
    # binary, and pointing the tool at it would fail at investigation time.
    primary = []
    if script:
        if os.sep not in script:
            # A console script is installed into the interpreter's bin directory.
            candidate = os.path.join(_venv_bin(), script)
            primary.append(candidate if os.path.exists(candidate) else
                           ('' if project.get('kind') == 'python' else script))
        else:
            primary.append(script)

    # The source fallback only helps when it does not need the same toolchain
    # that just failed - Python scripts run from the checkout, "go run ." does not.
    fallback_usable = project.get('kind') in ('python', 'shell', 'node')
    fallbacks = [fallback] if (fallback and (ok or fallback_usable)) else []

    record['entry'] = ''
    from_source = False
    for candidate in primary:
        if candidate and _entry_exists(candidate, dest):
            record['entry'] = candidate
            break
    if not record['entry']:
        for candidate in fallbacks:
            if candidate and _entry_exists(candidate, dest):
                record['entry'] = candidate
                from_source = True
                break

    if record['entry']:
        record['status'] = 'ready'
        if from_source:
            record['message'] = ('Running from source.' if message.startswith('No build step')
                                  else f'{message} Running from source.')
        else:
            record['message'] = message
    else:
        record['status'] = 'failed'
        if not ok:
            # The build step is the reason it could not run - say so.
            record['message'] = message or 'The build step failed.'
        else:
            record['message'] = ('Sherlock could not work out how to run this repository - '
                                  'no runnable entry point was found.')

    # The entry point may only be known after the build, so infer the argument
    # pattern once the command is final.
    record['args'] = _infer_args(dest, record['entry'] or record['fallback_entry'],
                                 record['types'])

    if record['status'] == 'ready' and not record['entry']:
        record['status'] = 'failed'
        record['message'] = 'Sherlock could not work out how to run this repository.'

    record['installed_at'] = datetime.utcnow().isoformat()
    _github_state['repos'][key] = record
    _save_github_state()
    return record


def _repo_record_view(record):
    """Public shape of an installed repository (no secrets involved)."""
    return {
        'key': record.get('key'),
        'full_name': record.get('full_name'),
        'description': record.get('description', ''),
        'stars': record.get('stars', 0),
        'language': record.get('language', ''),
        'url': record.get('url', ''),
        'kind': record.get('kind', 'github'),
        'status': record.get('status', 'ready'),
        'message': record.get('message', ''),
        'types': record.get('types', []),
        'entry': record.get('entry', ''),
        'args': record.get('args', '{target}'),
        'path': record.get('path', ''),
        'ref': record.get('ref', ''),
        'installed_at': record.get('installed_at'),
    }


def _stage_tool(investigation_type, stage):
    """The tool currently assigned to a stage."""
    override = _github_state.get('stage_tools', {}).get(
        f'{investigation_type}/{stage["id"]}')
    if override:
        return override
    if stage.get('repo'):
        return stage['repo']
    repos = stage.get('repos') or []
    return repos[0] if repos else None


def _resolve_stage_tools(investigation_type, stage):
    """The tools a stage should actually run."""
    override = _github_state.get('stage_tools', {}).get(
        f'{investigation_type}/{stage["id"]}')
    if override:
        return [override]
    tools = []
    if stage.get('repo'):
        tools.append(stage['repo'])
    for repo_key in (stage.get('repos') or []):
        if repo_key not in tools:
            tools.append(repo_key)
    return tools


def _tools_payload():
    tools = []
    for key, meta in OSINT_REPOS.items():
        tools.append({
            'key': key,
            'name': meta['name'],
            'kind': 'builtin',
            'description': meta.get('description', ''),
            'types': [meta.get('type', 'general')],
            'status': 'integrated',
            'url': meta.get('url', ''),
        })
    for key, record in _github_state['repos'].items():
        tools.append({
            'key': key,
            'name': record.get('full_name', key),
            'kind': 'user',
            'description': record.get('description', ''),
            'types': record.get('types', []),
            'status': record.get('status', 'ready'),
            'url': record.get('url', ''),
            'entry': record.get('entry', ''),
            'args': record.get('args', '{target}'),
        })
    return tools


@app.route('/api/github', methods=['GET'])
def github_status():
    """Token state, rate limit and the list of downloaded repositories."""
    token = _github_state.get('token')
    info = {'has_token': bool(token), 'login': None, 'rate': None, 'token_error': None}
    if token:
        try:
            user = _gh_call('/user', token=token)
            info['login'] = user.get('login')
        except GitHubError as exc:
            info['token_error'] = exc.message
        try:
            rate = _gh_call('/rate_limit', token=token)
            core = (rate.get('resources') or {}).get('core') or {}
            info['rate'] = {'limit': core.get('limit'),
                            'remaining': core.get('remaining'),
                            'reset': core.get('reset')}
        except GitHubError:
            pass

    return jsonify({
        'ok': True,
        'has_token': info['has_token'],
        'login': info['login'],
        'rate': info['rate'],
        'token_error': info['token_error'],
        'repos': [_repo_record_view(r) for r in _github_state['repos'].values()],
        'repos_dir': REPOS_DIR,
    })


@app.route('/api/github/token', methods=['POST'])
def github_save_token():
    """Store (or clear) the GitHub token after validating it."""
    data = request.get_json(silent=True) or {}
    token = (data.get('token') or '').strip()

    if not token:
        _github_state['token'] = None
        _save_github_state()
        return jsonify({'ok': True, 'has_token': False, 'login': None})

    try:
        payload, headers = _gh_request('/user', token=token)
    except urllib.error.HTTPError as exc:
        message = 'GitHub rejected the token (HTTP %d).' % exc.code
        if exc.code == 401:
            message = 'GitHub rejected the token (HTTP 401). It is invalid or expired.'
        return jsonify({'ok': False, 'error': message}), 401
    except urllib.error.URLError as exc:
        return jsonify({'ok': False, 'error': f'Could not reach GitHub: {exc.reason}.'}), 502

    _github_state['token'] = token
    _save_github_state()
    return jsonify({
        'ok': True,
        'has_token': True,
        'login': payload.get('login'),
        'scopes': headers.get('X-OAuth-Scopes') or headers.get('x-oauth-scopes') or '',
    })


@app.route('/api/github/search', methods=['GET'])
def github_search():
    """Search all of GitHub, or list the repositories the token can reach."""
    query = (request.args.get('q') or '').strip()
    scope = (request.args.get('scope') or 'public').strip()
    token = _github_state.get('token')

    try:
        if scope == 'mine':
            if not token:
                raise GitHubError('Add a GitHub token first - listing your own '
                                  'repositories needs one.', 400)
            items = _gh_call('/user/repos?per_page=100&sort=updated'
                             '&affiliation=owner,collaborator,organization_member',
                             token=token)
            if query:
                needle = query.lower()
                items = [r for r in items
                         if needle in f"{r.get('full_name', '')} "
                                       f"{r.get('description') or ''}".lower()]
            total = len(items)
        else:
            if not query:
                raise GitHubError('Type something to search for.', 400)
            params = urllib.parse.urlencode({
                'q': query, 'sort': 'stars', 'order': 'desc',
                'per_page': 40, 'page': 1,
            })
            payload = _gh_call('/search/repositories?' + params, token=token)
            items = payload.get('items', [])
            total = payload.get('total_count', len(items))
    except GitHubError as exc:
        return jsonify({'ok': False, 'error': exc.message}), exc.status

    installed = {r.get('full_name') for r in _github_state['repos'].values()}
    repos = []
    for item in items:
        view = _repo_view(item)
        view['installed'] = view['full_name'] in installed
        repos.append(view)

    return jsonify({'ok': True, 'scope': scope, 'total': total, 'repos': repos})


@app.route('/api/github/install', methods=['POST'])
def github_install():
    """Download a repository and configure it as an OSINT tool."""
    data = request.get_json(silent=True) or {}
    full_name = (data.get('full_name') or '').strip().strip('/')
    ref = (data.get('ref') or '').strip() or None
    meta = data.get('meta') or {}

    if full_name.count('/') != 1 or full_name.startswith('/'):
        return jsonify({'ok': False, 'error': 'Use the owner/name form, e.g. sherlock-project/sherlock.'}), 400

    try:
        record = _install_github_repo(full_name, ref=ref, meta=meta)
    except Exception as exc:
        return jsonify({'ok': False, 'error': f'Could not install {full_name}: {exc}'}), 500

    status_code = 200 if record.get('status') == 'ready' else 400
    return jsonify({
        'ok': record.get('status') == 'ready',
        'repo': _repo_record_view(record),
        'error': None if record.get('status') == 'ready' else record.get('message'),
    }), status_code


@app.route('/api/github/remove', methods=['POST'])
def github_remove():
    """Delete a downloaded repository and drop it from every pipeline stage."""
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip()
    record = _github_state['repos'].pop(key, None)

    if record:
        path = record.get('path')
        if path and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        for stage_key in [k for k, v in _github_state['stage_tools'].items() if v == key]:
            _github_state['stage_tools'].pop(stage_key)
        _save_github_state()

    return jsonify({'ok': True, 'removed': key})


@app.route('/api/github/args', methods=['POST'])
def github_set_args():
    """Change the command line pattern a downloaded tool expects."""
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip()
    args = (data.get('args') or '').strip()

    record = _github_state['repos'].get(key)
    if not record:
        return jsonify({'ok': False, 'error': 'That repository is not installed.'}), 404

    if args and '{target}' not in args:
        return jsonify({'ok': False,
                        'error': 'The pattern must contain {target}, e.g. -u {target}'}), 400

    record['args'] = args or '{target}'
    _save_github_state()
    return jsonify({'ok': True, 'key': key, 'args': record['args'],
                    'repo': _repo_record_view(record)})


@app.route('/api/tools', methods=['GET'])
def list_tools():
    """Every tool Sherlock can run: built-in integrations plus downloads."""
    return jsonify({'ok': True, 'tools': _tools_payload()})


@app.route('/api/pipeline-tools', methods=['GET'])
def get_pipeline_tools():
    """Pipeline stages with the tool assigned to each one."""
    types = {}
    for investigation_type, cfg in PIPELINE_CONFIG.items():
        stages = []
        for stage in cfg['stages']:
            stages.append({
                'id': stage['id'],
                'name': stage['name'],
                'type': stage['type'],
                'tool': _stage_tool(investigation_type, stage),
                'default_tool': stage.get('repo') or ((stage.get('repos') or [None])[0]),
                'uses_tool': stage['type'] in TOOL_STAGE_TYPES,
            })
        types[investigation_type] = stages

    return jsonify({'ok': True, 'types': types, 'tools': _tools_payload()})


@app.route('/api/pipeline-tools', methods=['POST'])
def set_pipeline_tool():
    """Assign a tool to a pipeline stage."""
    data = request.get_json(silent=True) or {}
    investigation_type = (data.get('type') or '').strip()
    stage_id = (data.get('stage_id') or '').strip()
    tool = (data.get('tool') or '').strip()

    stages = PIPELINE_CONFIG.get(investigation_type, {}).get('stages', [])
    if not any(s['id'] == stage_id for s in stages):
        return jsonify({'ok': False, 'error': 'Unknown pipeline stage.'}), 400

    if tool and tool not in {t['key'] for t in _tools_payload()}:
        return jsonify({'ok': False, 'error': 'Unknown tool.'}), 400

    key = f'{investigation_type}/{stage_id}'
    if tool:
        _github_state['stage_tools'][key] = tool
    else:
        _github_state['stage_tools'].pop(key, None)
    _save_github_state()

    return jsonify({'ok': True, 'type': investigation_type, 'stage_id': stage_id,
                    'tool': tool or None})


_load_github_state()


if __name__ == '__main__':
    port = int(os.environ.get('PORT') or 5000)
    if port == 0:
        port = 5000
    print(f"\n  Sherlock -> http://localhost:{port}\n", flush=True)
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
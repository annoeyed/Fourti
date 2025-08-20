#!/usr/bin/env python3
"""
GitHub 자동 패치 생성 및 적용 스크립트
FortiCode에서 생성된 시큐어 코드를 GitHub에 자동으로 패치로 적용합니다.
"""

import os
import json
import sys
import base64
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import re

class GitHubPatchCreator:
    def __init__(self, token: str, repo_owner: str, repo_name: str):
        self.token = token
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "FortiCode-Security-Patcher"
        }
    
    def create_branch(self, base_branch: str = "main", new_branch: str = None) -> str:
        """새로운 브랜치 생성"""
        if not new_branch:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_branch = f"security-patches-{timestamp}"
        
        # 기본 브랜치 정보 가져오기
        response = requests.get(
            f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/branches/{base_branch}",
            headers=self.headers
        )
        
        if response.status_code != 200:
            raise Exception(f"기본 브랜치 정보 가져오기 실패: {response.status_code}")
        
        base_sha = response.json()["commit"]["sha"]
        
        # 새 브랜치 생성
        response = requests.post(
            f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/git/refs",
            headers=self.headers,
            json={
                "ref": f"refs/heads/{new_branch}",
                "sha": base_sha
            }
        )
        
        if response.status_code != 201:
            raise Exception(f"브랜치 생성 실패: {response.status_code}")
        
        print(f"새 브랜치 생성됨: {new_branch}")
        return new_branch
    
    def get_file_content(self, file_path: str, branch: str = "main") -> Optional[Dict]:
        """파일 내용 가져오기"""
        # GitHub API 경로로 변환 - 로컬 경로를 저장소 경로로 변환
        api_path = self.convert_local_path_to_repo_path(file_path)
        
        response = requests.get(
            f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/contents/{api_path}",
            headers=self.headers,
            params={"ref": branch}
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"파일을 찾을 수 없음: {api_path}")
            return None
        else:
            raise Exception(f"파일 내용 가져오기 실패: {response.status_code}")
    
    def convert_local_path_to_repo_path(self, local_path: str) -> str:
        """로컬 파일 경로를 GitHub 저장소 경로로 변환"""
        # 로컬 경로에서 vulnbank 프로젝트 부분만 추출
        if "/mnt/c/Users/amiab/fourti/vulntest_total/vulnbank/" in local_path:
            # vulnbank 프로젝트 내부 파일들
            relative_path = local_path.replace("/mnt/c/Users/amiab/fourti/vulntest_total/vulnbank/", "")
            # vulnbank 저장소에는 vulnbank/ 디렉토리가 있으므로 경로 앞에 추가
            return f"vulnbank/{relative_path}"
        elif "/mnt/c/Users/amiab/fourti/forticode/" in local_path:
            # forticode 프로젝트 내부 파일들
            relative_path = local_path.replace("/mnt/c/Users/amiab/fourti/forticode/", "")
            return relative_path
        else:
            # 다른 경로는 그대로 반환
            return local_path
    
    def update_file(self, file_path: str, new_content: str, commit_message: str, branch: str) -> bool:
        """파일 업데이트"""
        # GitHub API 경로로 변환
        api_path = self.convert_local_path_to_repo_path(file_path)
        
        # 현재 파일 정보 가져오기
        current_file = self.get_file_content(api_path, branch)
        if not current_file:
            print(f"파일을 찾을 수 없어 건너뜀: {api_path}")
            return False
        
        # 파일 업데이트
        response = requests.put(
            f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/contents/{api_path}",
            headers=self.headers,
            json={
                "message": commit_message,
                "content": base64.b64encode(new_content.encode()).decode(),
                "sha": current_file["sha"],
                "branch": branch
            }
        )
        
        if response.status_code == 200:
            print(f"파일 업데이트 성공: {api_path}")
            return True
        else:
            print(f"파일 업데이트 실패: {api_path} - {response.status_code}")
            return False
    
    def create_pull_request(self, title: str, body: str, head_branch: str, base_branch: str = "main") -> Optional[str]:
        """Pull Request 생성"""
        response = requests.post(
            f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/pulls",
            headers=self.headers,
            json={
                "title": title,
                "body": body,
                "head": head_branch,
                "base": base_branch
            }
        )
        
        if response.status_code == 201:
            pr_url = response.json()["html_url"]
            print(f"Pull Request 생성됨: {pr_url}")
            return pr_url
        else:
            print(f"Pull Request 생성 실패: {response.status_code}")
            return None
    
    def apply_security_patches(self, secure_code_file: str, branch: str) -> Dict[str, Any]:
        """보안 패치 적용"""
        # 시큐어 코드 결과 로드
        with open(secure_code_file, 'r', encoding='utf-8') as f:
            secure_code_results = json.load(f)
        
        patches = secure_code_results.get('secure_code_patches', [])
        applied_count = 0
        failed_count = 0
        
        print(f"총 {len(patches)}개의 패치를 적용합니다...")
        
        for patch in patches:
            try:
                file_path = patch['file_path']
                finding_id = patch['finding_id']
                cwe = patch['secure_code_patch']
                severity = patch['severity']
                
                # 패치 내용에서 실제 코드 추출
                new_content = self.extract_patch_code(cwe, file_path)
                if not new_content:
                    print(f"패치 코드 추출 실패: {finding_id}")
                    failed_count += 1
                    continue
                
                # 커밋 메시지 생성
                commit_message = f"보안 패치 적용: {patch['original_vulnerability']['title']} (CWE-{cwe.split('-')[1] if '-' in cwe else cwe})"
                
                # 파일 업데이트
                if self.update_file(file_path, new_content, commit_message, branch):
                    applied_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                print(f"패치 적용 중 오류 발생: {e}")
                failed_count += 1
                continue
        
        return {
            'total_patches': len(patches),
            'applied_count': applied_count,
            'failed_count': failed_count
        }
    
    def extract_patch_code(self, patch_content: str, file_path: str) -> Optional[str]:
        """패치 내용에서 실제 코드 추출 및 적용"""
        try:
            # GitHub에서 파일 내용 가져오기
            api_path = self.convert_local_path_to_repo_path(file_path)
            file_info = self.get_file_content(api_path)
            
            if not file_info:
                print(f"  GitHub에서 파일을 찾을 수 없음: {api_path}")
                return None
            
            # 파일 내용 디코딩
            if 'content' in file_info:
                import base64
                original_content = base64.b64decode(file_info['content']).decode('utf-8')
            else:
                print(f"  파일 내용을 가져올 수 없음: {api_path}")
                return None
            
            # 패치 내용에서 안전한 코드 부분 추출
            if "```python" in patch_content:
                # Python 코드 블록에서 안전한 코드 추출
                code_start = patch_content.find("```python") + 9
                code_end = patch_content.find("```", code_start)
                if code_end > code_start:
                    safe_code_block = patch_content[code_start:code_end].strip()
                    
                    # 취약한 코드와 안전한 코드 분리
                    lines = safe_code_block.split('\n')
                    vulnerable_code = ""
                    secure_code = ""
                    
                    in_vulnerable_section = False
                    in_secure_section = False
                    
                    for line in lines:
                        if "취약한 코드" in line or "원본" in line:
                            in_vulnerable_section = True
                            in_secure_section = False
                        elif "안전한 코드" in line or "수정된 버전" in line:
                            in_vulnerable_section = False
                            in_secure_section = True
                        elif in_vulnerable_section and line.strip() and not line.startswith('#'):
                            vulnerable_code += line + '\n'
                        elif in_secure_section and line.strip() and not line.startswith('#'):
                            secure_code += line + '\n'
                    
                    # 원본 파일에서 취약한 코드를 찾아 안전한 코드로 교체
                    if vulnerable_code.strip() and secure_code.strip():
                        vulnerable_code = vulnerable_code.strip()
                        secure_code = secure_code.strip()
                        
                        if vulnerable_code in original_content:
                            new_content = original_content.replace(vulnerable_code, secure_code)
                            print(f"  코드 교체: {vulnerable_code[:50]}... → {secure_code[:50]}...")
                            return new_content
                        else:
                            print(f"  취약한 코드를 원본 파일에서 찾을 수 없음: {vulnerable_code[:50]}...")
                            return original_content
                    else:
                        print(f"  패치 내용에서 코드를 추출할 수 없음")
                        return original_content
            
            return original_content
            
        except Exception as e:
            print(f"패치 코드 추출 실패: {e}")
            return None

    def list_repository_files(self, path: str = "", branch: str = "main") -> List[str]:
        """저장소의 파일 목록 조회"""
        try:
            response = requests.get(
                f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/contents/{path}",
                headers=self.headers,
                params={"ref": branch}
            )
            
            if response.status_code == 200:
                contents = response.json()
                files = []
                
                if isinstance(contents, list):
                    for item in contents:
                        if item['type'] == 'file':
                            files.append(item['path'])
                        elif item['type'] == 'dir':
                            # 재귀적으로 하위 디렉토리 탐색
                            sub_files = self.list_repository_files(item['path'], branch)
                            files.extend(sub_files)
                
                return files
            else:
                print(f"파일 목록 조회 실패: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"파일 목록 조회 중 오류: {e}")
            return []
    
    def debug_repository_structure(self):
        """저장소 구조 디버깅"""
        print(f"\nGitHub 저장소 '{self.repo_owner}/{self.repo_name}' 구조 확인 중...")
        
        # 루트 디렉토리 파일 목록
        root_files = self.list_repository_files()
        
        if root_files:
            print("저장소에 있는 파일들:")
            for file in root_files[:20]:  # 처음 20개만 표시
                print(f"  - {file}")
            if len(root_files) > 20:
                print(f"  ... 및 {len(root_files) - 20}개 더")
        else:
            print("저장소에 파일이 없거나 접근할 수 없습니다.")
        
        return root_files

def main():
    """메인 함수"""
    print("GitHub 자동 패치 생성 시작")
    print("=" * 50)
    
    # GitHub 토큰 확인 (환경 변수에서 읽기)
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        print("GitHub 토큰이 설정되지 않았습니다. GITHUB_TOKEN 환경 변수를 설정해주세요.")
        return
    
    # vulnbank 저장소 정보 (기본값)
    repo_owner = "annoeyed"
    repo_name = "vulnbank"
    
    print(f"대상 저장소: {repo_owner}/{repo_name}")
    print("다른 저장소를 사용하려면 코드를 수정하세요.")
    
    # 시큐어 코드 파일 확인
    secure_code_file = "vulnbank_secure_code_generated.json"
    if not Path(secure_code_file).exists():
        print(f"시큐어 코드 파일을 찾을 수 없습니다: {secure_code_file}")
        return
    
    try:
        # GitHub 패치 생성기 초기화
        patcher = GitHubPatchCreator(github_token, repo_owner, repo_name)
        
        # 저장소 구조 확인
        repo_files = patcher.debug_repository_structure()
        
        if not repo_files:
            print("저장소에 접근할 수 없거나 파일이 없습니다. 토큰과 저장소 정보를 확인해주세요.")
            return
        
        # 새 브랜치 생성
        branch_name = patcher.create_branch()
        
        # 보안 패치 적용
        result = patcher.apply_security_patches(secure_code_file, branch_name)
        
        print(f"\n패치 적용 완료:")
        print(f"  총 패치: {result['total_patches']}개")
        print(f"  성공: {result['applied_count']}개")
        print(f"  실패: {result['failed_count']}개")
        
        # Pull Request 생성
        if result['applied_count'] > 0:
            pr_title = f"보안 취약점 자동 패치 적용 ({datetime.now().strftime('%Y-%m-%d')})"
            pr_body = f"""
## 보안 패치 자동 적용

이 Pull Request는 FortiCode를 통해 자동으로 생성된 보안 패치를 포함합니다.

### 적용된 패치
- 총 패치: {result['total_patches']}개
- 성공: {result['applied_count']}개
- 실패: {result['failed_count']}개

### 주요 보안 개선사항
- CWE 취약점 수정
- 안전한 코딩 패턴 적용
- 보안 모범 사례 구현

### 검토 필요사항
1. 자동 생성된 코드 검토
2. 테스트 실행
3. 보안 검증
            """
            
            pr_url = patcher.create_pull_request(pr_title, pr_body, branch_name)
            if pr_url:
                print(f"\nPull Request가 생성되었습니다: {pr_url}")
        
    except Exception as e:
        print(f"패치 생성 중 오류 발생: {e}")

if __name__ == "__main__":
    main()

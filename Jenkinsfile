def TRIVY = 'docker run --rm -v trivy-cache:/root/.cache -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD":/src aquasec/trivy:latest'

def scan(String name, String cmd) {
    sh """
        rc=0
        ${cmd} > reports/${name}.txt 2>&1 || rc=\$?
        cat reports/${name}.txt
        [ \$rc -eq 0 ] || [ "\$ENFORCE" != "true" ]
    """
}

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        COMPOSE_PROJECT_NAME = 'fullstack-react-springboot'
        ENFORCE = 'false'   // 'true' = security findings FAIL the build
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'rm -rf reports && mkdir -p reports && chmod 777 reports'
            }
        }

        stage('Secret Scan (Gitleaks)') {
            steps {
                script {
                    scan('1-gitleaks', 'docker run --rm -v "$PWD":/repo ghcr.io/gitleaks/gitleaks:latest detect --no-git --source /repo --redact --verbose --exit-code 1')
                }
            }
        }

        stage('SAST (Semgrep)') {
            steps {
                script {
                    scan('2-semgrep', 'docker run --rm -v "$PWD":/src -w /src semgrep/semgrep semgrep scan --config p/java --config p/typescript --config p/owasp-top-ten --metrics=off --severity ERROR --error --json-output=reports/semgrep.json')
                }
            }
        }

        stage('Dependency Scan (Trivy SCA)') {
            steps {
                script {
                    scan('3-trivy-sca', TRIVY + ' fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 /src')
                }
            }
        }

        stage('IaC and Dockerfile Scan') {
            steps {
                script {
                    scan('4-trivy-iac', TRIVY + ' config --severity HIGH,CRITICAL --exit-code 1 /src')
                }
            }
        }

        stage('Unit Tests') {
            steps {
                sh '''
                docker run --rm --user "$(id -u):$(id -g)" \
                  -v "$PWD/backend":/app -w /app \
                  maven:3.9-eclipse-temurin-17 \
                  mvn -q -Dmaven.repo.local=/tmp/.m2/repository test
                '''
            }
        }

        stage('Build Images') {
            steps {
                sh 'docker compose build'
            }
        }

        stage('Image Scan (Trivy)') {
            steps {
                script {
                    scan('5-image-backend', TRIVY + ' image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 fullstack-react-springboot-backend')
                    scan('5-image-frontend', TRIVY + ' image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 fullstack-react-springboot-frontend')
                }
            }
        }

        stage('SBOM') {
            steps {
                sh TRIVY + ' image --format cyclonedx --output /src/reports/sbom-backend.cdx.json fullstack-react-springboot-backend'
                sh TRIVY + ' image --format cyclonedx --output /src/reports/sbom-frontend.cdx.json fullstack-react-springboot-frontend'
            }
        }

        stage('Deploy') {
            steps {
                sh 'docker compose up -d'
            }
        }

        stage('Health Check') {
            steps {
                sh '''
                for i in $(seq 1 30); do
                  if curl -sf http://localhost:8081/actuator/health | grep -q UP; then
                    echo "Backend is UP"
                    exit 0
                  fi
                  sleep 5
                done
                echo "Backend health check failed"
                docker compose logs backend --tail 50
                exit 1
                '''
            }
        }

        stage('DAST (OWASP ZAP)') {
            steps {
                script {
                    scan('6-zap', 'docker run --rm --network host -v "$PWD/reports":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:3000 -r zap-report.html -I')
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        success {
            echo 'Pipeline passed. App: http://34.131.133.188:3000'
        }
        failure {
            echo 'Pipeline failed, check the console output'
        }
    }
}

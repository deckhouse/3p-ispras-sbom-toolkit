FROM python:3.14.2-slim-trixie

RUN apt-get update && \
    apt-get install -y git subversion mercurial curl bzr dpkg-dev && rm -rf /var/lib/apt/lists/* && rm -f /etc/apt/sources.list.d/*

RUN echo '#!/bin/bash\npython3 /usr/local/lib/sbom-checker/sbom-updater.py $@' > /usr/local/bin/sbom-updater && chmod +x /usr/local/bin/sbom-updater ; \
    echo '#!/bin/bash\npython3 /usr/local/lib/sbom-checker/sbom-checker.py $@' > /usr/local/bin/sbom-checker && chmod +x /usr/local/bin/sbom-checker ; \
    echo '#!/bin/bash\npython3 /usr/local/lib/sbom-checker/sbom-to-csv.py $@' > /usr/local/bin/sbom-to-csv && chmod +x /usr/local/bin/sbom-to-csv ; \
    echo '#!/bin/bash\npython3 /usr/local/lib/sbom-checker/sbom-to-odt.py $@' > /usr/local/bin/sbom-to-odt && chmod +x /usr/local/bin/sbom-to-odt ; \
    echo '#!/bin/bash\npython3 /usr/local/lib/sbom-checker/sbom-unifier.py $@' > /usr/local/bin/sbom-unifier && chmod +x /usr/local/bin/sbom-unifier ; 

COPY . /usr/local/lib/sbom-checker/

VOLUME ["/usr/local/lib/sbom-checker"]

RUN pip install --no-cache-dir -r /usr/local/lib/sbom-checker/requirements.txt

CMD ["sh"]
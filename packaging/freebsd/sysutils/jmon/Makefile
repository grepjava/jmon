PORTNAME=	jmon
DISTVERSION=	0.1.0
CATEGORIES=	sysutils

MAINTAINER=	grepjava@gmail.com
COMMENT=	nmon-style performance monitor with OpenTelemetry export
WWW=		https://github.com/CHANGEME/jmon

LICENSE=	BSD2CLAUSE

USES=		cargo
USE_GITHUB=	yes
GH_ACCOUNT=	CHANGEME
USE_RC_SUBR=	jmon

PLIST_FILES=	bin/jmon \
		"@sample etc/jmon.conf.sample" \
		share/man/man1/jmon.1.gz

post-install:
	${INSTALL_MAN} ${WRKSRC}/man/jmon.1 ${STAGEDIR}${PREFIX}/share/man/man1
	${INSTALL_DATA} ${WRKSRC}/contrib/jmon.conf.sample \
		${STAGEDIR}${PREFIX}/etc/jmon.conf.sample

# Before the first build, set GH_ACCOUNT/WWW, then run `make makesum` and
# `make cargo-crates > Makefile.crates` to pin the crate dependencies.
.include <bsd.port.mk>

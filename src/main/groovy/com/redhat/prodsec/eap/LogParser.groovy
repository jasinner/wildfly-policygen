package com.redhat.prodsec.eap
import java.security.Permission
import java.util.regex.*

class LogParser{
    //https://regex101.com/r/dT1bV4/3
    //This regex using negative lookahead to avoid terminating matches in name group that contain a '"' character
    //http://stackoverflow.com/questions/406230/regular-expression-to-match-line-that-doesnt-contain-a-word
    private static final Pattern modulePattern = ~/(?i)permission\s"\("(?<clazz>[^"]*+)"\s"(?<name>((?!"\s).)+)"(?:\s"(?<action>[^"]*+)")?\).*modules\/system\/layers\/base\/(?<module>[a-z\/]*)\/main/
    private static final Pattern deploymentPattern = ~/(?i)permission\s"\("(?<clazz>[^"]*+)"\s"(?<name>((?!"\s).)+)"(?:\s"(?<action>[^"]*+)")?\).*vfs:\\/content\\/(?<module>((?!\\/).)+)/
    private static Matcher m = null
    private EntryPoint.Modes mode

    LogParser(EntryPoint.Modes mode){
        this.mode = mode
    }

    def Map<String, Set<Permission>> parseFile(String fileName){
        Map<String, Set<Permission>> results = new HashMap<String, Set<Permission>>()
        new File(fileName).eachLine {
            line -> parseLine(line, results)
        }
        return results;
    }

    private parseLine(String line, Map<String, Set<Permission>> results){
        resetMatcher(line)
        while(m.find()){
			def module = m.group('module')
			def perm = PermissionFactory.createPermission(
				m.group('clazz'),
				m.group('name'),
				m.group('action'))
			def perms = results.get(module)
			if(perms == null){
				def newPerms = new HashSet<Permission>();
				newPerms.add(perm)
				results.put(module, newPerms)
			}
			else{
				perms.add(perm)
			}
        }
    }

    private void resetMatcher(String subject){
        if(m != null)
            m.reset(subject)
        else {
            switch(mode){
                case EntryPoint.Modes.MODULES: m = modulePattern.matcher(subject)
                    break
                default: m = deploymentPattern.matcher(subject)
                    break
            }

        }
    }


}

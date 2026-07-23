package me.fallenbreath.velocitywhitelist.config;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.constructor.ConstructorException;

import me.fallenbreath.velocitywhitelist.utils.FileUtils;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Regression guard for CVE-2022-1471 (unrestricted deserialisation): Configuration/PlayerList/
 * IpList parse config.yml/whitelist.yml/blacklist.yml/ipbans.yml, files that live in a directory
 * admins and admin tooling routinely hand-edit, so the loader they all share -
 * {@link FileUtils#newSafeYaml()} - must refuse to construct an attacker-chosen Java type from a
 * "!!fully.qualified.ClassName" tag rather than silently instantiating it.
 * <p>
 * This deliberately never calls a method that would trigger a real side effect (e.g.
 * URL#equals/openConnection perform a DNS lookup) - it only proves that construction of the
 * attacker-chosen type is blocked, which is the actual invariant this project's own code
 * guarantees, independent of whether a full RCE gadget chain happens to be reachable on a given
 * classpath, and independent of what SnakeYAML version happens to be resolved at any given time.
 */
class YamlDeserialisationSecurityTest
{
	@Test
	void safeYaml_rejectsArbitraryTypeTag()
	{
		String maliciousWhitelistYaml = "names: !!java.net.URL [\"http://example.invalid/\"]\n";

		assertThrows(ConstructorException.class, () -> FileUtils.newSafeYaml().load(maliciousWhitelistYaml),
				"a whitelist.yml value should never be able to make the parser instantiate an arbitrary Java type");
	}
}

/* ###
 * Runs the self test of the FridaHookGenerator against the program that is open.
 *
 * This is the way of launching it that costs the plugin nothing at all: a script is not part of the extension, so this
 * file and the fridahookgenerator/SelfTest directory can both be deleted without a single line of the plugin changing.
 *
 * From the graphical interface: Window -> Script Manager -> find this script -> run it. The report is printed in the
 * console.
 *
 * Without the graphical interface, which is what a build machine would do:
 *
 *   analyzeHeadless <the project directory> <the name of the project> -process <the binary> \
 *                   -postScript RunFridaHookGeneratorSelfTest.java
 *
 * Careful: without the graphical interface there is no tool, so the part of the self test that asks the plugin to generate
 * scripts cannot run, and it reports itself as skipped. The checks that do not need a tool still run and still fail the
 * script if something is wrong.
 *
 * The script throws when the self test fails, so that a build machine sees a failure instead of having to read the log.
 */
//@category FridaHookGenerator
//@keybinding
//@menupath
//@toolbar

import fridahookgenerator.SelfTest.SelfTestReport;
import fridahookgenerator.SelfTest.SelfTestRunner;
import ghidra.app.script.GhidraScript;

public class RunFridaHookGeneratorSelfTest extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if (currentProgram==null)
		{
			println("There is no program open, the self test has nothing to run against.");
			return;
		}

		/*
		 * The level can be given as the first argument of the script: LOW, MEDIUM or FULL. Without an argument the medium one
		 * is run, which is the one that is worth running before a commit.
		 *
		 *   analyzeHeadless ... -postScript RunFridaHookGeneratorSelfTest.java FULL
		 */
		SelfTestRunner.Level level=SelfTestRunner.Level.FULL;
		String[] the_arguments_of_the_script=getScriptArgs();
		if (the_arguments_of_the_script!=null && the_arguments_of_the_script.length>0)
		{
			String the_level_that_was_asked_for=the_arguments_of_the_script[0].trim().toUpperCase();
			if (the_level_that_was_asked_for.equals("LOW")) { level=SelfTestRunner.Level.LOW; }
			else if (the_level_that_was_asked_for.equals("MEDIUM")) { level=SelfTestRunner.Level.MEDIUM; }
			else if (the_level_that_was_asked_for.equals("FULL")) { level=SelfTestRunner.Level.FULL; }
			else
			{
				println("The level '"+the_arguments_of_the_script[0]+"' is not one of LOW, MEDIUM or FULL. Running the medium one.");
			}
		}

		SelfTestRunner runner=new SelfTestRunner(state.getTool(),currentProgram,level);
		SelfTestReport report=runner.run_everything();

		String text_of_the_report=report.return_the_whole_report();
		println(text_of_the_report);
		System.out.println(text_of_the_report);

		if (!report.did_the_self_test_pass().booleanValue())
		{
			/*Throwing is what makes analyzeHeadless report a failure for this script*/
			throw new Exception("The FridaHookGenerator self test found "
					+report.return_how_many_of_severity(fridahookgenerator.SelfTest.SelfTestFinding.Severity.ERROR)
					+" errors. The report above says what they are.");
		}
	}
}

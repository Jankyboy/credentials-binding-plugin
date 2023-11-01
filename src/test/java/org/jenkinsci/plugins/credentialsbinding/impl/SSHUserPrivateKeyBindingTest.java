/*
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.credentialsbinding.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.FilePath;
import hudson.Functions;
import hudson.security.ACL;
import hudson.util.Secret;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.cps.SnippetizerTester;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.steps.StepConfigTester;
import org.jenkinsci.plugins.workflow.test.steps.SemaphoreStep;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

import org.junit.ClassRule;
import org.jvnet.hudson.test.BuildWatcher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SSHUserPrivateKeyBindingTest {

    @Rule public RestartableJenkinsRule story = new RestartableJenkinsRule();
    @ClassRule public static BuildWatcher bw = new BuildWatcher();
    @Rule public TemporaryFolder tmp = new TemporaryFolder();

    private static class DummyPrivateKey extends BaseCredentials implements SSHUserPrivateKey, Serializable {

        private final String id;
        private final String user;
        boolean usernameSecret = true;
        private final Secret passphrase;
        private final String keyContent;

        DummyPrivateKey(String id, String user, String passphrase, final String keyContent) {
            this.id = id;
            this.user = user;
            this.passphrase = Secret.fromString(passphrase);
            this.keyContent = keyContent;
        }

        @NonNull
        @Override
        public String getId() {
            return id;
        }

        @NonNull
        @Override
        public String getPrivateKey() {
            return keyContent;
        }

        @Override
        public Secret getPassphrase() {
            return passphrase;
        }

        @NonNull
        @Override
        public List<String> getPrivateKeys() {
            return Collections.singletonList(keyContent);
        }

        @NonNull
        @Override
        public String getUsername() {
            return user;
        }

        @Override
        public boolean isUsernameSecret() {
            return usernameSecret;
        }

        @NonNull
        @Override
        public String getDescription() {
            return "";
        }

        @Override
        public CredentialsScope getScope() {
            return CredentialsScope.GLOBAL;
        }
    }

    @Test public void configRoundTrip() {
        story.then(r -> {
            SnippetizerTester st = new SnippetizerTester(r);
            SSHUserPrivateKey c = new DummyPrivateKey("creds", "bob", "secret", "the-key");
            CredentialsProvider.lookupStores(story.j.jenkins).iterator().next().addCredentials(Domain.global(), c);
            SSHUserPrivateKeyBinding binding = new SSHUserPrivateKeyBinding("keyFile", "creds");
            BindingStep s = new StepConfigTester(story.j).configRoundTrip(new BindingStep(Collections.singletonList(binding)));
            st.assertRoundTrip(s, "withCredentials([sshUserPrivateKey(credentialsId: 'creds', keyFileVariable: 'keyFile')]) {\n    // some block\n}");
            r.assertEqualDataBoundBeans(s.getBindings(), Collections.singletonList(binding));
            binding.setPassphraseVariable("passphrase");
            binding.setUsernameVariable("user");
            s = new StepConfigTester(story.j).configRoundTrip(new BindingStep(Collections.singletonList(binding)));
            st.assertRoundTrip(s, "withCredentials([sshUserPrivateKey(credentialsId: 'creds', keyFileVariable: 'keyFile', passphraseVariable: 'passphrase', usernameVariable: 'user')]) {\n    // some block\n}");
            r.assertEqualDataBoundBeans(s.getBindings(), Collections.singletonList(binding));
        });
    }

    @Test public void basics() {
        final String credentialsId = "creds";
        final String username = "bob";
        final String passphrase = "s3cr3t";
        final String keyContent = "the-key";
        story.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                SSHUserPrivateKey c = new DummyPrivateKey(credentialsId, username, passphrase, keyContent);
                CredentialsProvider.lookupStores(story.j.jenkins).iterator().next().addCredentials(Domain.global(), c);
                WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, "p");
                String script;
                if (Functions.isWindows()) {
                    script =
                        "    bat '''\n"
                        + "      echo %THEUSER%:%THEPASS% > out.txt\n"
                        + "      type \"%THEKEY%\" > key.txt"
                        + "    '''\n";
                } else {
                    script =
                        "    sh '''\n"
                        + "      echo $THEUSER:$THEPASS > out.txt\n"
                        + "      cat \"$THEKEY\" > key.txt"
                        + "    '''\n";
                }
                p.setDefinition(new CpsFlowDefinition(""
                        + "node {\n"
                        + "  withCredentials([sshUserPrivateKey(keyFileVariable: 'THEKEY', passphraseVariable: 'THEPASS', usernameVariable: 'THEUSER', credentialsId: '" + credentialsId + "')]) {\n"
                        + "    semaphore 'basics'\n"
                        + script
                        + "  }\n"
                        + "}", true));
                WorkflowRun b = p.scheduleBuild2(0).waitForStart();
                SemaphoreStep.waitForStart("basics/1", b);
            }
        });
        story.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                WorkflowJob p = story.j.jenkins.getItemByFullName("p", WorkflowJob.class);
                assertNotNull(p);
                WorkflowRun b = p.getBuildByNumber(1);
                assertNotNull(b);
                SemaphoreStep.success("basics/1", null);
                story.j.waitForCompletion(b);
                story.j.assertBuildStatusSuccess(b);
                story.j.assertLogNotContains(username, b);
                story.j.assertLogNotContains(passphrase, b);
                FilePath out = story.j.jenkins.getWorkspaceFor(p).child("out.txt");
                assertTrue(out.exists());
                assertEquals(username + ":" + passphrase, out.readToString().trim());

                FilePath key = story.j.jenkins.getWorkspaceFor(p).child("key.txt");
                assertTrue(key.exists());
                assertEquals(keyContent, key.readToString().trim());

                ((DummyPrivateKey) CredentialsProvider.lookupCredentialsInItemGroup(SSHUserPrivateKey.class, story.j.jenkins, ACL.SYSTEM2, Collections.emptyList()).get(0)).usernameSecret = false;
                SemaphoreStep.success("basics/2", null);
                b = story.j.buildAndAssertSuccess(p);
                story.j.assertLogContains(username, b);
                story.j.assertLogNotContains(passphrase, b);
            }
        });
    }

    @Test public void noUsernameOrPassphrase() {
        final String credentialsId = "creds";
        final String keyContent = "the-key";
        story.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                SSHUserPrivateKey c = new DummyPrivateKey(credentialsId, "", "", keyContent);
                CredentialsProvider.lookupStores(story.j.jenkins).iterator().next().addCredentials(Domain.global(), c);
                WorkflowJob p = story.j.jenkins.createProject(WorkflowJob.class, "p");
                String script;
                if (Functions.isWindows()) {
                    script =
                        "    bat '''\n"
                        + "      type \"%THEKEY%\" > key.txt"
                        + "    '''\n";
                } else {
                    script =
                        "    sh '''\n"
                        + "      cat \"$THEKEY\" > key.txt"
                        + "    '''\n";
                }
                p.setDefinition(new CpsFlowDefinition(""
                        + "node {\n"
                        + "  withCredentials([sshUserPrivateKey(keyFileVariable: 'THEKEY', credentialsId: '" + credentialsId + "')]) {\n"
                        + "    semaphore 'basics'\n"
                        + script
                        + "  }\n"
                        + "}", true));
                WorkflowRun b = p.scheduleBuild2(0).waitForStart();
                SemaphoreStep.waitForStart("basics/1", b);
            }
        });
        story.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                WorkflowJob p = story.j.jenkins.getItemByFullName("p", WorkflowJob.class);
                assertNotNull(p);
                WorkflowRun b = p.getBuildByNumber(1);
                assertNotNull(b);
                SemaphoreStep.success("basics/1", null);
                story.j.waitForCompletion(b);
                story.j.assertBuildStatusSuccess(b);

                FilePath key = story.j.jenkins.getWorkspaceFor(p).child("key.txt");
                assertTrue(key.exists());
                assertEquals(keyContent, key.readToString().trim());
            }
        });
    }
}

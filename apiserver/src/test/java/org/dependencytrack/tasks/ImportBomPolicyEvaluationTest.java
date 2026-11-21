/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.NotificationTestUtil.getNotificationOutbox;
import static org.dependencytrack.notification.NotificationTestUtil.truncateNotificationOutbox;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_POLICY_VIOLATION;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.persistence.jdbi.ConfigPropertyTestUtil.createConfigProperty;
import static org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger.ANALYSIS_TRIGGER_BOM_UPLOAD;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for the per-project policy evaluation and notification behavior
 * that is triggered by SBOM ingestion.
 */
class ImportBomPolicyEvaluationTest extends PersistenceCapableTest {

    private static final String BOM_TEMPLATE = """
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.5",
              "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
              "version": 1,
              "components": [
                {
                  "type": "library",
                  "group": "com.example",
                  "name": "%s",
                  "version": "1.0.0",
                  "purl": "pkg:maven/com.example/%s@1.0.0"
                }
              ]
            }
            """;

    private DexEngine dexEngineMock;
    private FileStorage fileStorage;
    private ImportBomActivity activity;

    @BeforeEach
    void beforeEach() {
        dexEngineMock = mock(DexEngine.class);
        fileStorage = new MemoryFileStorage();
        activity = new ImportBomActivity(fileStorage, dexEngineMock, false);

        // Enable processing of CycloneDX BOMs.
        createConfigProperty(ACCEPT_ARTIFACT_CYCLONEDX, "true");

        // Required for notifications to be emitted.
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
    }

    @Test
    void triggersPerProjectAnalysisWorkflowUponBomImportTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        final CreateWorkflowRunRequest<?> analyzeRequest = captureAnalyzeWorkflowRequest();
        assertThat(analyzeRequest.concurrencyKey())
                .isEqualTo(AnalyzeProjectWorkflow.concurrencyKeyForProject(project.getUuid()));
        assertThat(analyzeRequest.argument()).isInstanceOf(AnalyzeProjectWorkflowArg.class);
        final var analyzeArg = (AnalyzeProjectWorkflowArg) analyzeRequest.argument();
        assertThat(analyzeArg.getProjectUuid()).isEqualTo(project.getUuid().toString());
        assertThat(analyzeArg.getTrigger()).isEqualTo(ANALYSIS_TRIGGER_BOM_UPLOAD);
        assertThat(analyzeRequest.labels())
                .isNotNull()
                .containsValue(project.getUuid().toString())
                .containsValue("bom-upload");
    }

    @Test
    void usesBomUploadTokenInAnalysisWorkflowInstanceIdTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var bomUploadToken = UUID.randomUUID();

        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), bomUploadToken));

        final CreateWorkflowRunRequest<?> analyzeRequest = captureAnalyzeWorkflowRequest();
        assertThat(analyzeRequest.workflowInstanceId())
                .isEqualTo(AnalyzeProjectWorkflow.instanceIdForBomUpload(bomUploadToken));
        assertThat(analyzeRequest.labels()).isNotNull().containsValue(bomUploadToken.toString());
    }

    @Test
    void emitsBomConsumedAndProcessedNotificationsTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        assertThat(getNotificationOutbox())
                .satisfiesExactly(
                        notification -> {
                            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
                            assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED);
                        },
                        notification -> {
                            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
                            assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED);
                        });
    }

    @Test
    void emitsProcessingFailedNotificationAndSkipsAnalysisForInvalidBomTest() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        assertThatExceptionOfType(TerminalApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(
                        null,
                        buildArg(
                                project,
                                storeBomFile("definitely not a BOM".getBytes(StandardCharsets.UTF_8)),
                                UUID.randomUUID())));

        assertThat(getNotificationOutbox())
                .satisfiesExactly(notification -> {
                    assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
                    assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
                    assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
                });

        // No analysis, and thus no policy evaluation, must be triggered for failed imports.
        verifyNoInteractions(dexEngineMock);
    }

    @Test
    void createsPolicyViolationForComponentFromImportedBomTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        createNameMatchingPolicy("acme-lib");

        new CelPolicyEngine().evaluateProject(project.getUuid());

        assertThat(qm.getAllPolicyViolations(project))
                .satisfiesExactly(violation -> {
                    assertThat(violation.getType()).isEqualTo(PolicyViolation.Type.OPERATIONAL);
                    assertThat(violation.getComponent().getName()).isEqualTo("acme-lib");
                });
    }

    @Test
    void emitsPolicyViolationNotificationForComponentFromImportedBomTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        createNameMatchingPolicy("acme-lib");

        // Discard the BOM_CONSUMED / BOM_PROCESSED notifications from the import.
        truncateNotificationOutbox();

        new CelPolicyEngine().evaluateProject(project.getUuid());

        assertThat(getNotificationOutbox())
                .satisfiesExactly(notification -> {
                    assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
                    assertThat(notification.getGroup()).isEqualTo(GROUP_POLICY_VIOLATION);
                    assertThat(notification.getSubject().is(PolicyViolationSubject.class)).isTrue();
                    final var subject = notification.getSubject().unpack(PolicyViolationSubject.class);
                    assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
                    assertThat(subject.getComponent().getName()).isEqualTo("acme-lib");
                    assertThat(subject.getPolicyViolation().getType()).isEqualTo("OPERATIONAL");
                });
    }

    @Test
    void doesNotApplyPoliciesLimitedToOtherProjectsTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Project otherProject = qm.createProject("Other Example", null, "1.0", null, null, null, null, false);
        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        final Policy policy = createNameMatchingPolicy("acme-lib");
        policy.setProjects(List.of(otherProject));
        qm.persist(policy);

        truncateNotificationOutbox();

        new CelPolicyEngine().evaluateProject(project.getUuid());

        assertThat(qm.getAllPolicyViolations(project)).isEmpty();
        assertThat(getNotificationOutbox()).isEmpty();
    }

    @Test
    void evaluatesProjectConditionsPerProjectTest() throws Exception {
        final Project projectA = qm.createProject("acme-app-a", null, "1.0", null, null, null, null, false);
        final Project projectB = qm.createProject("acme-app-b", null, "1.0", null, null, null, null, false);
        activity.execute(null, buildArg(projectA, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));
        activity.execute(null, buildArg(projectB, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                """
                project.name == "acme-app-a"
                """,
                PolicyViolation.Type.OPERATIONAL);

        new CelPolicyEngine().evaluateProject(projectA.getUuid());
        new CelPolicyEngine().evaluateProject(projectB.getUuid());

        assertThat(qm.getAllPolicyViolations(projectA)).hasSize(1);
        assertThat(qm.getAllPolicyViolations(projectB)).isEmpty();
    }

    @Test
    void reconcilesViolationsWhenBomIsReImportedTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        createNameMatchingPolicy("acme-lib");

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(project)).hasSize(1);

        // Re-import a BOM that no longer contains the violating component.
        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("other-lib")), UUID.randomUUID()));

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(project)).isEmpty();
    }

    @Test
    void emitsNoPolicyViolationNotificationWhenNoPoliciesApplyTest() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        activity.execute(null, buildArg(project, storeBomFile(bomWithComponent("acme-lib")), UUID.randomUUID()));

        truncateNotificationOutbox();

        new CelPolicyEngine().evaluateProject(project.getUuid());

        assertThat(qm.getAllPolicyViolations(project)).isEmpty();
        assertThat(getNotificationOutbox()).isEmpty();
    }

    private Policy createNameMatchingPolicy(final String componentName) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                "component.name == \"%s\"".formatted(componentName),
                PolicyViolation.Type.OPERATIONAL);
        return policy;
    }

    private CreateWorkflowRunRequest<?> captureAnalyzeWorkflowRequest() {
        @SuppressWarnings("unchecked")
        final ArgumentCaptor<CreateWorkflowRunRequest<?>> captor =
                ArgumentCaptor.forClass(CreateWorkflowRunRequest.class);
        verify(dexEngineMock, atLeastOnce()).createRun(captor.capture());
        return captor.getAllValues().stream()
                .filter(request -> "analyze-project".equals(request.workflowName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No analyze-project workflow run was requested"));
    }

    private static byte[] bomWithComponent(final String componentName) {
        return BOM_TEMPLATE
                .formatted(componentName, componentName)
                .getBytes(StandardCharsets.UTF_8);
    }

    private ImportBomArg buildArg(
            final Project project, final FileMetadata bomFileMetadata, final UUID bomUploadToken) {
        return ImportBomArg.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .setProjectName(project.getName())
                .setProjectVersion(project.getVersion() != null ? project.getVersion() : "")
                .setBomUploadToken(bomUploadToken.toString())
                .setBomFileMetadata(bomFileMetadata)
                .build();
    }

    private FileMetadata storeBomFile(final byte[] bomBytes) throws Exception {
        return fileStorage.store(
                "test/%s-%s".formatted(ImportBomPolicyEvaluationTest.class.getSimpleName(), UUID.randomUUID()),
                new ByteArrayInputStream(bomBytes));
    }

}

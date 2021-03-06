/*
 * SonarQube
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.server.computation.qualitymodel;

import java.util.Arrays;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.sonar.api.rules.RuleType;
import org.sonar.api.utils.Duration;
import org.sonar.core.issue.DefaultIssue;
import org.sonar.core.util.Uuids;
import org.sonar.server.computation.batch.TreeRootHolderRule;
import org.sonar.server.computation.component.Component;
import org.sonar.server.computation.component.FileAttributes;
import org.sonar.server.computation.component.ReportComponent;
import org.sonar.server.computation.component.VisitorsCrawler;
import org.sonar.server.computation.issue.ComponentIssuesRepositoryRule;
import org.sonar.server.computation.issue.FillComponentIssuesVisitorRule;
import org.sonar.server.computation.measure.Measure;
import org.sonar.server.computation.measure.MeasureRepositoryRule;
import org.sonar.server.computation.metric.MetricRepositoryRule;
import org.sonar.server.computation.qualitymodel.RatingGrid.Rating;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.sonar.api.issue.Issue.RESOLUTION_FIXED;
import static org.sonar.api.measures.CoreMetrics.DEVELOPMENT_COST;
import static org.sonar.api.measures.CoreMetrics.DEVELOPMENT_COST_KEY;
import static org.sonar.api.measures.CoreMetrics.EFFORT_TO_REACH_MAINTAINABILITY_RATING_A;
import static org.sonar.api.measures.CoreMetrics.EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY;
import static org.sonar.api.measures.CoreMetrics.NCLOC;
import static org.sonar.api.measures.CoreMetrics.NCLOC_KEY;
import static org.sonar.api.measures.CoreMetrics.RELIABILITY_RATING;
import static org.sonar.api.measures.CoreMetrics.RELIABILITY_RATING_KEY;
import static org.sonar.api.measures.CoreMetrics.SECURITY_RATING;
import static org.sonar.api.measures.CoreMetrics.SECURITY_RATING_KEY;
import static org.sonar.api.measures.CoreMetrics.SQALE_DEBT_RATIO;
import static org.sonar.api.measures.CoreMetrics.SQALE_DEBT_RATIO_KEY;
import static org.sonar.api.measures.CoreMetrics.SQALE_RATING;
import static org.sonar.api.measures.CoreMetrics.SQALE_RATING_KEY;
import static org.sonar.api.measures.CoreMetrics.TECHNICAL_DEBT;
import static org.sonar.api.measures.CoreMetrics.TECHNICAL_DEBT_KEY;
import static org.sonar.api.rule.Severity.BLOCKER;
import static org.sonar.api.rule.Severity.CRITICAL;
import static org.sonar.api.rule.Severity.INFO;
import static org.sonar.api.rule.Severity.MAJOR;
import static org.sonar.api.rule.Severity.MINOR;
import static org.sonar.api.rules.RuleType.BUG;
import static org.sonar.api.rules.RuleType.CODE_SMELL;
import static org.sonar.api.rules.RuleType.VULNERABILITY;
import static org.sonar.server.computation.component.Component.Type.DIRECTORY;
import static org.sonar.server.computation.component.Component.Type.FILE;
import static org.sonar.server.computation.component.Component.Type.MODULE;
import static org.sonar.server.computation.component.Component.Type.PROJECT;
import static org.sonar.server.computation.component.ReportComponent.builder;
import static org.sonar.server.computation.measure.Measure.newMeasureBuilder;
import static org.sonar.server.computation.measure.MeasureRepoEntry.entryOf;
import static org.sonar.server.computation.measure.MeasureRepoEntry.toEntries;
import static org.sonar.server.computation.qualitymodel.RatingGrid.Rating.A;
import static org.sonar.server.computation.qualitymodel.RatingGrid.Rating.B;
import static org.sonar.server.computation.qualitymodel.RatingGrid.Rating.C;
import static org.sonar.server.computation.qualitymodel.RatingGrid.Rating.D;
import static org.sonar.server.computation.qualitymodel.RatingGrid.Rating.E;

public class QualityModelMeasuresVisitorForReportTest {

  static final String LANGUAGE_KEY_1 = "lKey1";
  static final String LANGUAGE_KEY_2 = "lKey2";

  static final double[] RATING_GRID = new double[] {0.1, 0.2, 0.5, 1};

  static final long DEV_COST_LANGUAGE_1 = 30;
  static final long DEV_COST_LANGUAGE_2 = 42;

  static final int PROJECT_REF = 1;
  static final int MODULE_REF = 12;
  static final int DIRECTORY_REF = 123;
  static final int FILE_1_REF = 1231;
  static final int FILE_2_REF = 1232;

  static final Component ROOT_PROJECT = builder(Component.Type.PROJECT, PROJECT_REF).setKey("project")
    .addChildren(
      builder(MODULE, MODULE_REF).setKey("module")
        .addChildren(
          builder(DIRECTORY, DIRECTORY_REF).setKey("directory")
            .addChildren(
              builder(FILE, FILE_1_REF).setFileAttributes(new FileAttributes(false, LANGUAGE_KEY_1)).setKey("file1").build(),
              builder(FILE, FILE_2_REF).setFileAttributes(new FileAttributes(false, LANGUAGE_KEY_1)).setKey("file2").build())
            .build())
        .build())
    .build();

  @Rule
  public TreeRootHolderRule treeRootHolder = new TreeRootHolderRule();

  @Rule
  public MetricRepositoryRule metricRepository = new MetricRepositoryRule()
    .add(NCLOC)
    .add(DEVELOPMENT_COST)
    .add(TECHNICAL_DEBT)
    .add(SQALE_DEBT_RATIO)
    .add(SQALE_RATING)
    .add(EFFORT_TO_REACH_MAINTAINABILITY_RATING_A)
    .add(RELIABILITY_RATING)
    .add(SECURITY_RATING);

  @Rule
  public MeasureRepositoryRule measureRepository = MeasureRepositoryRule.create(treeRootHolder, metricRepository);

  @Rule
  public ComponentIssuesRepositoryRule componentIssuesRepositoryRule = new ComponentIssuesRepositoryRule(treeRootHolder);

  @Rule
  public FillComponentIssuesVisitorRule fillComponentIssuesVisitorRule = new FillComponentIssuesVisitorRule(componentIssuesRepositoryRule, treeRootHolder);

  private RatingSettings ratingSettings = mock(RatingSettings.class);

  private VisitorsCrawler underTest;

  @Before
  public void setUp() {
    // assumes rating configuration is consistent
    when(ratingSettings.getRatingGrid()).thenReturn(new RatingGrid(RATING_GRID));
    when(ratingSettings.getDevCost(LANGUAGE_KEY_1)).thenReturn(DEV_COST_LANGUAGE_1);
    when(ratingSettings.getDevCost(LANGUAGE_KEY_2)).thenReturn(DEV_COST_LANGUAGE_2);

    underTest = new VisitorsCrawler(Arrays.asList(
      fillComponentIssuesVisitorRule,
      new QualityModelMeasuresVisitor(metricRepository, measureRepository, ratingSettings, componentIssuesRepositoryRule)));
  }

  @Test
  public void measures_created_for_project_are_all_zero_when_they_have_no_FILE_child() {
    ReportComponent root = builder(PROJECT, 1).build();
    treeRootHolder.setRoot(root);

    underTest.visit(root);

    assertThat(toEntries(measureRepository.getRawMeasures(root)))
      .containsOnly(
        entryOf(DEVELOPMENT_COST_KEY, newMeasureBuilder().create("0")),
        entryOf(SQALE_DEBT_RATIO_KEY, newMeasureBuilder().create(0d, 1)),
        entryOf(SQALE_RATING_KEY, createMaintainabilityRatingMeasure(A)),
        entryOf(EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY, newMeasureBuilder().create(0L)),
        entryOf(RELIABILITY_RATING_KEY, createMaintainabilityRatingMeasure(A)),
        entryOf(SECURITY_RATING_KEY, createMaintainabilityRatingMeasure(A)));
  }

  @Test
  public void compute_development_cost() {
    ReportComponent root = builder(PROJECT, 1)
      .addChildren(
        builder(MODULE, 11)
          .addChildren(
            builder(DIRECTORY, 111)
              .addChildren(
                createFileComponent(LANGUAGE_KEY_1, 1111),
                createFileComponent(LANGUAGE_KEY_2, 1112),
                builder(FILE, 1113).setFileAttributes(new FileAttributes(true, LANGUAGE_KEY_1)).build())
              .build(),
            builder(DIRECTORY, 112)
              .addChildren(
                createFileComponent(LANGUAGE_KEY_2, 1121))
              .build())
          .build(),
        builder(MODULE, 12)
          .addChildren(
            builder(DIRECTORY, 121)
              .addChildren(
                createFileComponent(LANGUAGE_KEY_1, 1211))
              .build(),
            builder(DIRECTORY, 122).build())
          .build(),
        builder(MODULE, 13).build())
      .build();

    treeRootHolder.setRoot(root);

    int ncloc1111 = 10;
    addRawMeasure(NCLOC_KEY, 1111, ncloc1111);

    int ncloc1112 = 10;
    addRawMeasure(NCLOC_KEY, 1112, ncloc1112);

    int nclocValue1121 = 30;
    addRawMeasure(NCLOC_KEY, 1121, nclocValue1121);

    int ncloc1211 = 20;
    addRawMeasure(NCLOC_KEY, 1211, ncloc1211);

    underTest.visit(root);

    // verify measures on files
    verifyAddedRawMeasure(1111, DEVELOPMENT_COST_KEY, Long.toString(ncloc1111 * DEV_COST_LANGUAGE_1));
    verifyAddedRawMeasure(1112, DEVELOPMENT_COST_KEY, Long.toString(ncloc1111 * DEV_COST_LANGUAGE_2));
    verifyNoAddedRawMeasure(1113);
    verifyAddedRawMeasure(1121, DEVELOPMENT_COST_KEY, Long.toString(nclocValue1121 * DEV_COST_LANGUAGE_2));
    verifyAddedRawMeasure(1211, DEVELOPMENT_COST_KEY, Long.toString(ncloc1211 * DEV_COST_LANGUAGE_1));

    // directory has no children => no file => 0 everywhere and A rating
    verifyAddedRawMeasure(122, DEVELOPMENT_COST_KEY, "0");

    // directory has children => dev cost is aggregated
    verifyAddedRawMeasure(111, DEVELOPMENT_COST_KEY, Long.toString(
      ncloc1111 * DEV_COST_LANGUAGE_1 +
        ncloc1112 * DEV_COST_LANGUAGE_2));
    verifyAddedRawMeasure(112, DEVELOPMENT_COST_KEY, Long.toString(nclocValue1121 * DEV_COST_LANGUAGE_2));
    verifyAddedRawMeasure(121, DEVELOPMENT_COST_KEY, Long.toString(ncloc1211 * DEV_COST_LANGUAGE_1));

    // just for fun, we didn't define any debt on module => they must all have rating A
    verifyAddedRawMeasure(11, DEVELOPMENT_COST_KEY, Long.toString(
      ncloc1111 * DEV_COST_LANGUAGE_1 +
        ncloc1112 * DEV_COST_LANGUAGE_2 +
        nclocValue1121 * DEV_COST_LANGUAGE_2));
    verifyAddedRawMeasure(12, DEVELOPMENT_COST_KEY, Long.toString(ncloc1211 * DEV_COST_LANGUAGE_1));
    verifyAddedRawMeasure(13, DEVELOPMENT_COST_KEY, "0");
    verifyAddedRawMeasure(1, DEVELOPMENT_COST_KEY, Long.toString(
      ncloc1111 * DEV_COST_LANGUAGE_1 +
        ncloc1112 * DEV_COST_LANGUAGE_2 +
        nclocValue1121 * DEV_COST_LANGUAGE_2 +
        ncloc1211 * DEV_COST_LANGUAGE_1));
  }

  @Test
  public void compute_maintainability_debt_ratio_measure() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);

    int file1Ncloc = 10;
    addRawMeasure(NCLOC_KEY, FILE_1_REF, file1Ncloc);
    long file1MaintainabilityCost = 100L;
    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_1_REF, file1MaintainabilityCost);

    int file2Ncloc = 5;
    addRawMeasure(NCLOC_KEY, FILE_2_REF, file2Ncloc);
    long file2MaintainabilityCost = 1L;
    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_2_REF, file2MaintainabilityCost);

    long directoryMaintainabilityCost = 100L;
    addRawMeasure(TECHNICAL_DEBT_KEY, DIRECTORY_REF, directoryMaintainabilityCost);

    long moduleMaintainabilityCost = 100L;
    addRawMeasure(TECHNICAL_DEBT_KEY, MODULE_REF, moduleMaintainabilityCost);

    long projectMaintainabilityCost = 1000L;
    addRawMeasure(TECHNICAL_DEBT_KEY, PROJECT_REF, projectMaintainabilityCost);

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(FILE_1_REF, SQALE_DEBT_RATIO_KEY, file1MaintainabilityCost * 1d / (file1Ncloc * DEV_COST_LANGUAGE_1) * 100);
    verifyAddedRawMeasure(FILE_2_REF, SQALE_DEBT_RATIO_KEY, file2MaintainabilityCost * 1d / (file2Ncloc * DEV_COST_LANGUAGE_1) * 100);
    verifyAddedRawMeasure(DIRECTORY_REF, SQALE_DEBT_RATIO_KEY, directoryMaintainabilityCost * 1d / ((file1Ncloc + file2Ncloc) * DEV_COST_LANGUAGE_1) * 100);
    verifyAddedRawMeasure(MODULE_REF, SQALE_DEBT_RATIO_KEY, moduleMaintainabilityCost * 1d / ((file1Ncloc + file2Ncloc) * DEV_COST_LANGUAGE_1) * 100);
    verifyAddedRawMeasure(PROJECT_REF, SQALE_DEBT_RATIO_KEY, projectMaintainabilityCost * 1d / ((file1Ncloc + file2Ncloc) * DEV_COST_LANGUAGE_1) * 100);
  }

  @Test
  public void compute_maintainability_rating_measure() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);

    addRawMeasure(NCLOC_KEY, FILE_1_REF, 10);
    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_1_REF, 100L);

    addRawMeasure(NCLOC_KEY, FILE_2_REF, 5);
    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_2_REF, 1L);

    addRawMeasure(TECHNICAL_DEBT_KEY, DIRECTORY_REF, 100L);
    addRawMeasure(TECHNICAL_DEBT_KEY, MODULE_REF, 100L);
    addRawMeasure(TECHNICAL_DEBT_KEY, PROJECT_REF, 1000L);

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(FILE_1_REF, SQALE_RATING_KEY, C);
    verifyAddedRawMeasure(FILE_2_REF, SQALE_RATING_KEY, A);
    verifyAddedRawMeasure(DIRECTORY_REF, SQALE_RATING_KEY, C);
    verifyAddedRawMeasure(MODULE_REF, SQALE_RATING_KEY, C);
    verifyAddedRawMeasure(PROJECT_REF, SQALE_RATING_KEY, E);
  }

  @Test
  public void compute_effort_to_maintainability_rating_A_measure() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);

    int file1Ncloc = 10;
    long file1Effort = 100L;
    addRawMeasure(NCLOC_KEY, FILE_1_REF, file1Ncloc);
    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_1_REF, file1Effort);

    int file2Ncloc = 5;
    long file2Effort = 20L;
    addRawMeasure(NCLOC_KEY, FILE_2_REF, file2Ncloc);
    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_2_REF, file2Effort);

    long dirEffort = 120L;
    addRawMeasure(TECHNICAL_DEBT_KEY, DIRECTORY_REF, dirEffort);

    long moduleEffort = 120L;
    addRawMeasure(TECHNICAL_DEBT_KEY, MODULE_REF, moduleEffort);

    long projectEffort = 150L;
    addRawMeasure(TECHNICAL_DEBT_KEY, PROJECT_REF, projectEffort);

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(FILE_1_REF, EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY,
      (long) (file1Effort - RATING_GRID[0] * file1Ncloc * DEV_COST_LANGUAGE_1));
    verifyAddedRawMeasure(FILE_2_REF, EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY,
      (long) (file2Effort - RATING_GRID[0] * file2Ncloc * DEV_COST_LANGUAGE_1));
    verifyAddedRawMeasure(DIRECTORY_REF, EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY,
      (long) (dirEffort - RATING_GRID[0] * (file1Ncloc + file2Ncloc) * DEV_COST_LANGUAGE_1));
    verifyAddedRawMeasure(MODULE_REF, EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY,
      (long) (moduleEffort - RATING_GRID[0] * (file1Ncloc + file2Ncloc) * DEV_COST_LANGUAGE_1));
    verifyAddedRawMeasure(PROJECT_REF, EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY,
      (long) (projectEffort - RATING_GRID[0] * (file1Ncloc + file2Ncloc) * DEV_COST_LANGUAGE_1));
  }

  @Test
  public void compute_0_effort_to_maintainability_rating_A_when_effort_is_lower_than_dev_cost() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);

    addRawMeasure(NCLOC_KEY, FILE_1_REF, 10);
    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_1_REF, 2L);

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(FILE_1_REF, EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY, 0L);
  }

  @Test
  public void effort_to_maintainability_rating_A_is_same_as_effort_when_no_dev_cost() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);

    addRawMeasure(TECHNICAL_DEBT_KEY, FILE_1_REF, 100L);

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(FILE_1_REF, EFFORT_TO_REACH_MAINTAINABILITY_RATING_A_KEY, 100);
  }

  @Test
  public void compute_reliability_rating() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);
    fillComponentIssuesVisitorRule.setIssues(FILE_1_REF, newBugIssue(10L, MAJOR), newBugIssue(1L, MAJOR),
      // Should not be taken into account
      newVulnerabilityIssue(5L, MINOR));
    fillComponentIssuesVisitorRule.setIssues(FILE_2_REF, newBugIssue(2L, CRITICAL), newBugIssue(3L, MINOR),
      // Should not be taken into account
      newBugIssue(10L, BLOCKER).setResolution(RESOLUTION_FIXED));
    fillComponentIssuesVisitorRule.setIssues(MODULE_REF, newBugIssue(7L, BLOCKER));

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(FILE_1_REF, RELIABILITY_RATING_KEY, C);
    verifyAddedRawMeasure(FILE_2_REF, RELIABILITY_RATING_KEY, D);
    verifyAddedRawMeasure(DIRECTORY_REF, RELIABILITY_RATING_KEY, D);
    verifyAddedRawMeasure(MODULE_REF, RELIABILITY_RATING_KEY, E);
    verifyAddedRawMeasure(PROJECT_REF, RELIABILITY_RATING_KEY, E);
  }

  @Test
  public void compute_security_rating() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);
    fillComponentIssuesVisitorRule.setIssues(FILE_1_REF, newVulnerabilityIssue(10L, MAJOR), newVulnerabilityIssue(1L, MAJOR),
      // Should not be taken into account
      newBugIssue(1L, MAJOR));
    fillComponentIssuesVisitorRule.setIssues(FILE_2_REF, newVulnerabilityIssue(2L, CRITICAL), newVulnerabilityIssue(3L, MINOR),
      // Should not be taken into account
      newVulnerabilityIssue(10L, BLOCKER).setResolution(RESOLUTION_FIXED));
    fillComponentIssuesVisitorRule.setIssues(MODULE_REF, newVulnerabilityIssue(7L, BLOCKER));

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(FILE_1_REF, SECURITY_RATING_KEY, C);
    verifyAddedRawMeasure(FILE_2_REF, SECURITY_RATING_KEY, D);
    verifyAddedRawMeasure(DIRECTORY_REF, SECURITY_RATING_KEY, D);
    verifyAddedRawMeasure(MODULE_REF, SECURITY_RATING_KEY, E);
    verifyAddedRawMeasure(PROJECT_REF, SECURITY_RATING_KEY, E);
  }

  @Test
  public void compute_E_reliability_and_security_rating_on_blocker_issue() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);
    fillComponentIssuesVisitorRule.setIssues(FILE_1_REF, newBugIssue(10L, BLOCKER), newVulnerabilityIssue(1L, BLOCKER),
      // Should not be taken into account
      newBugIssue(1L, MAJOR));

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(PROJECT_REF, RELIABILITY_RATING_KEY, E);
    verifyAddedRawMeasure(PROJECT_REF, SECURITY_RATING_KEY, E);
  }

  @Test
  public void compute_D_reliability_and_security_rating_on_critical_issue() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);
    fillComponentIssuesVisitorRule.setIssues(FILE_1_REF, newBugIssue(10L, CRITICAL), newVulnerabilityIssue(15L, CRITICAL),
      // Should not be taken into account
      newCodeSmellIssue(1L, MAJOR));

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(PROJECT_REF, RELIABILITY_RATING_KEY, D);
    verifyAddedRawMeasure(PROJECT_REF, SECURITY_RATING_KEY, D);
  }

  @Test
  public void compute_C_reliability_and_security_rating_on_major_issue() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);
    fillComponentIssuesVisitorRule.setIssues(FILE_1_REF, newBugIssue(10L, MAJOR), newVulnerabilityIssue(15L, MAJOR),
      // Should not be taken into account
      newCodeSmellIssue(1L, MAJOR));

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(PROJECT_REF, RELIABILITY_RATING_KEY, C);
    verifyAddedRawMeasure(PROJECT_REF, SECURITY_RATING_KEY, C);
  }

  @Test
  public void compute_B_reliability_and_security_rating_on_minor_issue() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);
    fillComponentIssuesVisitorRule.setIssues(FILE_1_REF, newBugIssue(10L, MINOR), newVulnerabilityIssue(15L, MINOR),
      // Should not be taken into account
      newCodeSmellIssue(1L, MAJOR));

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(PROJECT_REF, RELIABILITY_RATING_KEY, B);
    verifyAddedRawMeasure(PROJECT_REF, SECURITY_RATING_KEY, B);
  }

  @Test
  public void compute_A_reliability_and_security_rating_on_info_issue() throws Exception {
    treeRootHolder.setRoot(ROOT_PROJECT);
    fillComponentIssuesVisitorRule.setIssues(FILE_1_REF, newBugIssue(10L, INFO), newVulnerabilityIssue(15L, INFO),
      // Should not be taken into account
      newCodeSmellIssue(1L, MAJOR));

    underTest.visit(ROOT_PROJECT);

    verifyAddedRawMeasure(PROJECT_REF, RELIABILITY_RATING_KEY, A);
    verifyAddedRawMeasure(PROJECT_REF, SECURITY_RATING_KEY, A);
  }

  private void addRawMeasure(String metricKey, int componentRef, long value) {
    measureRepository.addRawMeasure(componentRef, metricKey, newMeasureBuilder().create(value));
  }

  private void addRawMeasure(String metricKey, int componentRef, int value) {
    measureRepository.addRawMeasure(componentRef, metricKey, newMeasureBuilder().create(value));
  }

  private void verifyAddedRawMeasure(int componentRef, String metricKey, long value) {
    assertThat(toEntries(measureRepository.getAddedRawMeasures(componentRef))).contains(entryOf(metricKey, newMeasureBuilder().create(value)));
  }

  private void verifyAddedRawMeasure(int componentRef, String metricKey, double value) {
    assertThat(toEntries(measureRepository.getAddedRawMeasures(componentRef))).contains(entryOf(metricKey, newMeasureBuilder().create(value, 1)));
  }

  private void verifyAddedRawMeasure(int componentRef, String metricKey, Rating rating) {
    assertThat(toEntries(measureRepository.getAddedRawMeasures(componentRef))).contains(entryOf(metricKey, newMeasureBuilder().create(rating.getIndex(), rating.name())));
  }

  private void verifyAddedRawMeasure(int componentRef, String metricKey, String value) {
    assertThat(toEntries(measureRepository.getAddedRawMeasures(componentRef))).contains(entryOf(metricKey, newMeasureBuilder().create(value)));
  }

  private void verifyNoAddedRawMeasure(int componentRef) {
    assertThat(toEntries(measureRepository.getAddedRawMeasures(componentRef))).isEmpty();
  }

  private static ReportComponent createFileComponent(String languageKey1, int fileRef) {
    return builder(FILE, fileRef).setFileAttributes(new FileAttributes(false, languageKey1)).build();
  }

  private static Measure createMaintainabilityRatingMeasure(Rating rating) {
    return newMeasureBuilder().create(rating.getIndex(), rating.name());
  }

  private static DefaultIssue newBugIssue(long effort, String severity) {
    return newIssue(effort, severity, BUG);
  }

  private static DefaultIssue newVulnerabilityIssue(long effort, String severity) {
    return newIssue(effort, severity, VULNERABILITY);
  }

  private static DefaultIssue newCodeSmellIssue(long effort, String severity) {
    return newIssue(effort, severity, CODE_SMELL);
  }

  private static DefaultIssue newIssue(long effort, String severity, RuleType type) {
    return newIssue(severity, type)
      .setEffort(Duration.create(effort));
  }

  private static DefaultIssue newIssue(String severity, RuleType type) {
    return new DefaultIssue()
      .setKey(Uuids.create())
      .setSeverity(severity)
      .setType(type);
  }

}

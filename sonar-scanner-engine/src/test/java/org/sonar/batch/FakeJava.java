package org.sonar.batch;

import org.sonar.api.resources.AbstractLanguage;

public class FakeJava extends AbstractLanguage {

  public static final String KEY = "java";
  public static final FakeJava INSTANCE = new FakeJava();

  public FakeJava() {
    super(KEY, "Java");
  }

  @Override
  public String[] getFileSuffixes() {
    return new String[] {".java", ".jav"};
  }

}

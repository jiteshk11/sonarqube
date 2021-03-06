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
package org.sonar.db.property;

import com.google.common.base.MoreObjects;
import java.util.Objects;

public class PropertyDto {
  private Long id;
  private String key;
  private String value;
  private Long resourceId;
  private Long userId;

  public Long getId() {
    return id;
  }

  public PropertyDto setId(Long id) {
    this.id = id;
    return this;
  }

  public String getKey() {
    return key;
  }

  public PropertyDto setKey(String key) {
    this.key = key;
    return this;
  }

  public String getValue() {
    return value;
  }

  public PropertyDto setValue(String value) {
    this.value = value;
    return this;
  }

  public Long getResourceId() {
    return resourceId;
  }

  public PropertyDto setResourceId(Long resourceId) {
    this.resourceId = resourceId;
    return this;
  }

  public Long getUserId() {
    return userId;
  }

  public PropertyDto setUserId(Long userId) {
    this.userId = userId;
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    final PropertyDto other = (PropertyDto) obj;

    return Objects.equals(this.key, other.key)
      && Objects.equals(this.value, other.value)
      && Objects.equals(this.userId, other.userId)
      && Objects.equals(this.resourceId, other.resourceId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.key, this.value, this.resourceId, this.userId);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
      .addValue(this.key)
      .addValue(this.value)
      .addValue(this.resourceId)
      .addValue(this.userId)
      .toString();
  }
}

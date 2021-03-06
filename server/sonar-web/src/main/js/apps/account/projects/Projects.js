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
import React from 'react';
import ProjectCard from './ProjectCard';
import ProjectsSearch from './ProjectsSearch';
import ListFooter from '../../../components/controls/ListFooter';
import { projectsListType } from './propTypes';
import { translate } from '../../../helpers/l10n';

export default class Projects extends React.Component {
  static propTypes = {
    projects: projectsListType.isRequired,
    total: React.PropTypes.number.isRequired,
    loading: React.PropTypes.bool.isRequired,
    search: React.PropTypes.func.isRequired,
    loadMore: React.PropTypes.func.isRequired
  };

  render () {
    const { projects } = this.props;

    return (
        <div className="page page-limited account-projects">
          <header className="page-header">
            <h1 className="page-title">
              My Projects
            </h1>
            <div className="pull-right">
              <ProjectsSearch onSearch={this.props.search}/>
            </div>
            <div className="page-description">
              {translate('my_account.projects.description')}
            </div>
          </header>

          {projects.length === 0 && (
              <div className="js-no-results">
                {translate('no_results')}
              </div>
          )}

          {projects.length > 0 && (
              <ul className="account-projects-list">
                {projects.map(project => (
                    <li key={project.key}>
                      <ProjectCard project={project}/>
                    </li>
                ))}
              </ul>
          )}

          {projects.length > 0 && (
              <ListFooter
                  count={projects.length}
                  total={this.props.total}
                  ready={!this.props.loading}
                  loadMore={this.props.loadMore}/>
          )}
        </div>
    );
  }
}

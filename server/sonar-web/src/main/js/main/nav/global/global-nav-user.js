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
import Avatar from '../../../components/ui/Avatar';
import RecentHistory from '../component/RecentHistory';
import { translate } from '../../../helpers/l10n';

export default React.createClass({
  renderAuthenticated() {
    return (
        <li className="dropdown">
          <a className="dropdown-toggle" data-toggle="dropdown" href="#">
            <Avatar email={window.SS.userEmail} size={20}/>&nbsp;
            {window.SS.userName}&nbsp;<i className="icon-dropdown"/>
          </a>
          <ul className="dropdown-menu dropdown-menu-right">
            <li>
              <a href={`${window.baseUrl}/account/`}>{translate('my_account.page')}</a>
            </li>
            <li>
              <a onClick={this.handleLogout} href="#">{translate('layout.logout')}</a>
            </li>
          </ul>
        </li>
    );
  },

  renderAnonymous() {
    return (
        <li>
          <a onClick={this.handleLogin} href="#">{translate('layout.login')}</a>
        </li>
    );
  },

  handleLogin(e) {
    e.preventDefault();
    const returnTo = window.location.pathname + window.location.search;
    window.location = `${window.baseUrl}/sessions/new?return_to=${encodeURIComponent(returnTo)}${window.location.hash}`;
  },

  handleLogout(e) {
    e.preventDefault();
    RecentHistory.clear();
    window.location = `${window.baseUrl}/sessions/logout`;
  },

  render() {
    const isUserAuthenticated = !!window.SS.user;
    return isUserAuthenticated ? this.renderAuthenticated() : this.renderAnonymous();
  }
});

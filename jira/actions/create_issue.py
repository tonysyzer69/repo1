from lib.base import BaseJiraAction
from lib.formatters import to_issue_dict

__all__ = [
    'CreateJiraIssueAction'
]


class CreateJiraIssueAction(BaseJiraAction):

    def run(self, summary, assignee, type, components=None, description=None,
            project=None, extra_fields=None):
        project = project or self.config['project']
        data = {
            'project': {'key': project},
            'summary': summary,
            'assignee': {'name': assignee},
            'components': components,
            'issuetype': {'name': type}
        }

        if description:
            data['description'] = description

        if extra_fields:
            data.update(extra_fields)

	_components = []
	for component in components:	
		_components.append({"name": component})
	
	data['components'] = _components

        issue = self._client.create_issue(fields=data)
        result = to_issue_dict(issue)
        return result

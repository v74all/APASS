import asyncio
from typing import Dict, List, Any

class HookManager:
    async def batch_operation(self, operations_list: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List]:
        if not isinstance(operations_list, dict) or 'operations' not in operations_list:
            raise ValueError("Invalid operations_list format")

        result = {
            'successful': [],
            'failed': []
        }
        tasks = []
        for op in operations_list.get('operations', []):
            tasks.append(self._execute_operation(op, result))
        await asyncio.gather(*tasks)
        return result

    async def _execute_operation(self, op: Dict[str, Any], result: Dict[str, List]) -> None:
        if not isinstance(op, dict):
            result['failed'].append({'error': 'Invalid operation format'})
            return

        try:
            await asyncio.sleep(0)
            result['successful'].append(op)
        except Exception as e:
            result['failed'].append({
                'operation': op.get('operation', 'unknown'),
                'class_name': op.get('class_name', 'unknown'),
                'method_name': op.get('method_name', 'unknown'),
                'error': str(e)
            })
